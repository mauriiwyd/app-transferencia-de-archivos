import hashlib
import hmac
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import threading
import time
import tkinter as tk
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import quote, urlsplit


APP_NAME = "GameTransfer"
MAX_FILE_SIZE = 50 * 1024**3
SERVER_PORT = 8765
FREE_LINK_DAYS = 7
PASSWORD_ITERATIONS = 310_000
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def app_data_directory():
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    directory = Path(base) / APP_NAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt.hex(), digest.hex()


def format_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


class TransferDatabase:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        with self.lock:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    email TEXT PRIMARY KEY,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS shares (
                    code TEXT PRIMARY KEY,
                    owner_email TEXT NOT NULL REFERENCES users(email),
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            self.connection.commit()

    def create_user(self, email, password):
        salt, password_hash = hash_password(password)
        try:
            with self.lock:
                self.connection.execute(
                    "INSERT INTO users(email, salt, password_hash) VALUES (?, ?, ?)",
                    (email, salt, password_hash),
                )
                self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, email, password):
        with self.lock:
            row = self.connection.execute(
                "SELECT salt, password_hash FROM users WHERE email = ?", (email,)
            ).fetchone()
        if row is None:
            return False
        _, candidate = hash_password(password, bytes.fromhex(row["salt"]))
        return hmac.compare_digest(candidate, row["password_hash"])

    def user_exists(self, email):
        with self.lock:
            return self.connection.execute(
                "SELECT 1 FROM users WHERE email = ?", (email,)
            ).fetchone() is not None

    def change_password(self, email, password):
        salt, password_hash = hash_password(password)
        with self.lock:
            cursor = self.connection.execute(
                "UPDATE users SET salt = ?, password_hash = ? WHERE email = ?",
                (salt, password_hash, email),
            )
            self.connection.commit()
            return cursor.rowcount == 1

    def add_share(self, email, file_path):
        path = Path(file_path)
        stat = path.stat()
        code = secrets.token_urlsafe(24)
        created_at = time.time()
        expires_at = created_at + FREE_LINK_DAYS * 24 * 60 * 60
        with self.lock:
            self.connection.execute(
                """INSERT INTO shares
                   (code, owner_email, file_path, file_name, file_size, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (code, email, str(path), path.name, stat.st_size, created_at, expires_at),
            )
            self.connection.commit()
        return code

    def get_share(self, code):
        with self.lock:
            row = self.connection.execute(
                "SELECT * FROM shares WHERE code = ?", (code,)
            ).fetchone()
            return dict(row) if row else None

    def list_shares(self, email):
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM shares WHERE owner_email = ? ORDER BY created_at DESC",
                (email,),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_share(self, email, code):
        with self.lock:
            self.connection.execute(
                "DELETE FROM shares WHERE owner_email = ? AND code = ?",
                (email, code),
            )
            self.connection.commit()


def create_request_handler(database):
    class DownloadHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            code = urlsplit(self.path).path.removeprefix("/s/")
            if not code or code == urlsplit(self.path).path:
                self.send_error(404, "Enlace no encontrado")
                return

            share = database.get_share(code)
            if share is None:
                self.send_error(404, "Enlace no encontrado o eliminado")
                return
            if share["expires_at"] <= time.time():
                self.send_error(410, "Este enlace ha caducado")
                return

            path = Path(share["file_path"])
            try:
                file_handle = path.open("rb")
                file_size = path.stat().st_size
            except OSError:
                self.send_error(404, "El archivo original ya no está disponible")
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(file_size))
            self.send_header(
                "Content-Disposition",
                f"attachment; filename*=UTF-8''{quote(share['file_name'], safe='')}",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                with file_handle:
                    while block := file_handle.read(1024 * 1024):
                        self.wfile.write(block)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format, *_args):
            del _format, _args
            return

    return DownloadHandler


class AplicacionTransferencia(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} | Envío de archivos")
        self.geometry("720x650")
        self.minsize(650, 570)
        self.configure(bg="#17231f")
        self.protocol("WM_DELETE_WINDOW", self.cerrar)

        self.database = TransferDatabase(app_data_directory() / "gametransfer.sqlite3")
        self.usuario_actual = None
        self.codigo_recuperacion = None
        self.correo_recuperacion = None
        self.expira_recuperacion = 0
        self.ip_local = self.obtener_ip_local()
        self.error_servidor = None
        self.servidor = None
        self.iniciar_servidor()

        self.contenedor = tk.Frame(self, bg="#17231f")
        self.contenedor.pack(fill="both", expand=True, padx=36, pady=28)
        self.estilo = ttk.Style(self)
        self.estilo.theme_use("clam")
        self.estilo.configure(
            "Treeview", background="#24332d", fieldbackground="#24332d",
            foreground="#f4f2e9", rowheight=30, borderwidth=0
        )
        self.estilo.configure(
            "Treeview.Heading", background="#31443b", foreground="#f4f2e9",
            font=("Segoe UI", 9, "bold")
        )
        self.mostrar_login()

    @staticmethod
    def obtener_ip_local():
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 80))
            return probe.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            probe.close()

    def iniciar_servidor(self):
        try:
            handler = create_request_handler(self.database)
            self.servidor = ThreadingHTTPServer(("0.0.0.0", SERVER_PORT), handler)
            threading.Thread(target=self.servidor.serve_forever, daemon=True).start()
        except OSError as error:
            self.error_servidor = str(error)

    def cerrar(self):
        if self.servidor is not None:
            self.servidor.shutdown()
            self.servidor.server_close()
        self.database.connection.close()
        self.destroy()

    def limpiar_pantalla(self):
        for widget in self.contenedor.winfo_children():
            widget.destroy()

    def titulo(self, texto, subtitulo=None):
        tk.Label(
            self.contenedor, text=texto, font=("Segoe UI", 23, "bold"),
            bg="#17231f", fg="#f4f2e9"
        ).pack(anchor="w", pady=(0, 4))
        if subtitulo:
            tk.Label(
                self.contenedor, text=subtitulo, font=("Segoe UI", 10),
                bg="#17231f", fg="#b5c3b8", wraplength=620, justify="left"
            ).pack(anchor="w", pady=(0, 20))

    def etiqueta(self, texto):
        tk.Label(
            self.contenedor, text=texto, bg="#17231f", fg="#d8e1d8",
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(12, 4))

    def entrada(self, ocultar=False):
        campo = tk.Entry(
            self.contenedor, font=("Segoe UI", 12), relief="flat",
            bg="#f4f2e9", fg="#17231f", insertbackground="#17231f",
            show="*" if ocultar else ""
        )
        campo.pack(fill="x", ipady=9)
        return campo

    def boton(self, texto, comando, color="#d27a43"):
        return tk.Button(
            self.contenedor, text=texto, command=comando, cursor="hand2",
            bg=color, fg="#17231f", activebackground="#e59b65",
            activeforeground="#17231f", relief="flat", bd=0,
            font=("Segoe UI", 10, "bold"), padx=16, pady=10
        )

    def boton_texto(self, texto, comando):
        tk.Button(
            self.contenedor, text=texto, command=comando, cursor="hand2",
            bg="#17231f", fg="#92c6ae", activebackground="#17231f",
            activeforeground="#f4f2e9", relief="flat", bd=0,
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(12, 0))

    def mostrar_login(self):
        self.limpiar_pantalla()
        self.titulo("GameTransfer", "Comparte archivos de juegos de hasta 50 GB")
        self.etiqueta("Correo electrónico")
        correo = self.entrada()
        self.etiqueta("Contraseña")
        password = self.entrada(ocultar=True)

        def intentar_login(_event=None):
            del _event
            email = correo.get().strip().lower()
            if self.database.verify_user(email, password.get()):
                self.usuario_actual = email
                self.mostrar_dashboard()
            else:
                messagebox.showerror(
                    "No se pudo iniciar sesión",
                    "Correo o contraseña incorrectos. Vuelve a intentarlo.",
                    parent=self,
                )

        self.boton("Iniciar sesión", intentar_login).pack(fill="x", pady=(22, 0))
        password.bind("<Return>", intentar_login)
        self.boton_texto("Crear cuenta", self.mostrar_registro)
        self.boton_texto("¿Olvidaste tu contraseña?", self.mostrar_recuperacion)

    def mostrar_registro(self):
        self.limpiar_pantalla()
        self.titulo("Crear cuenta", "Tus datos se guardan en este ordenador.")
        self.etiqueta("Correo electrónico")
        correo = self.entrada()
        self.etiqueta("Contraseña (mínimo 8 caracteres)")
        password = self.entrada(ocultar=True)
        self.etiqueta("Repite la contraseña")
        confirmar = self.entrada(ocultar=True)

        def registrar():
            email = correo.get().strip().lower()
            secret = password.get()
            if not EMAIL_PATTERN.fullmatch(email):
                messagebox.showerror("Correo no válido", "Escribe un correo válido.", parent=self)
                return
            if len(secret) < 8:
                messagebox.showerror(
                    "Contraseña muy corta", "Usa al menos 8 caracteres.", parent=self
                )
                return
            if secret != confirmar.get():
                messagebox.showerror("No coincide", "Las contraseñas no coinciden.", parent=self)
                return
            if not self.database.create_user(email, secret):
                messagebox.showerror("Cuenta existente", "Ese correo ya tiene una cuenta.", parent=self)
                return
            messagebox.showinfo("Cuenta creada", "Ya puedes iniciar sesión.", parent=self)
            self.mostrar_login()

        self.boton("Crear cuenta", registrar).pack(fill="x", pady=(22, 0))
        self.boton_texto("Volver a iniciar sesión", self.mostrar_login)

    def enviar_correo(self, destino, codigo):
        host = os.environ.get("SMTP_HOST")
        usuario = os.environ.get("SMTP_USER")
        password = os.environ.get("SMTP_PASSWORD")
        remitente = os.environ.get("SMTP_FROM", usuario or "")
        port = int(os.environ.get("SMTP_PORT", "465"))
        if not all((host, usuario, password, remitente)):
            raise RuntimeError(
                "El envío de correo no está configurado. Define SMTP_HOST, SMTP_PORT, "
                "SMTP_USER, SMTP_PASSWORD y SMTP_FROM."
            )

        message = EmailMessage()
        message["Subject"] = "Código para recuperar GameTransfer"
        message["From"] = remitente
        message["To"] = destino
        message.set_content(
            f"Tu código de recuperación es {codigo}. Caduca en 10 minutos. "
            "Si no solicitaste este cambio, ignora este mensaje."
        )
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context()) as smtp:
                smtp.login(usuario, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(usuario, password)
                smtp.send_message(message)

    def mostrar_recuperacion(self):
        self.limpiar_pantalla()
        self.titulo("Recuperar contraseña", "Te enviaremos un código de un solo uso por correo.")
        self.etiqueta("Correo de tu cuenta")
        correo = self.entrada()

        def solicitar_codigo():
            email = correo.get().strip().lower()
            if not EMAIL_PATTERN.fullmatch(email):
                messagebox.showerror("Correo no válido", "Escribe un correo válido.", parent=self)
                return
            if not self.database.user_exists(email):
                messagebox.showinfo(
                    "Solicitud recibida",
                    "Si el correo corresponde a una cuenta, recibirás un código.",
                    parent=self,
                )
                return
            code = f"{secrets.randbelow(1_000_000):06d}"
            try:
                self.enviar_correo(email, code)
            except (OSError, smtplib.SMTPException, RuntimeError, ValueError) as error:
                messagebox.showerror("No se pudo enviar el correo", str(error), parent=self)
                return
            self.codigo_recuperacion = code
            self.correo_recuperacion = email
            self.expira_recuperacion = time.time() + 600
            self.mostrar_cambio_contrasena()

        self.boton("Enviar código", solicitar_codigo).pack(fill="x", pady=(22, 0))
        self.boton_texto("Volver", self.mostrar_login)

    def mostrar_cambio_contrasena(self):
        self.limpiar_pantalla()
        self.titulo("Cambiar contraseña", f"Código enviado a {self.correo_recuperacion}")
        self.etiqueta("Código de 6 dígitos")
        codigo = self.entrada()
        self.etiqueta("Nueva contraseña (mínimo 8 caracteres)")
        password = self.entrada(ocultar=True)
        self.etiqueta("Repite la contraseña")
        confirmar = self.entrada(ocultar=True)

        def cambiar():
            if time.time() > self.expira_recuperacion:
                self.codigo_recuperacion = None
                messagebox.showerror("Código caducado", "Solicita un código nuevo.", parent=self)
                self.mostrar_recuperacion()
                return
            if not secrets.compare_digest(codigo.get().strip(), self.codigo_recuperacion or ""):
                messagebox.showerror("Código incorrecto", "Revisa el código e inténtalo otra vez.", parent=self)
                return
            if len(password.get()) < 8 or password.get() != confirmar.get():
                messagebox.showerror(
                    "Contraseña no válida",
                    "Usa al menos 8 caracteres y confirma que ambas coincidan.",
                    parent=self,
                )
                return
            self.database.change_password(self.correo_recuperacion, password.get())
            self.codigo_recuperacion = None
            messagebox.showinfo("Contraseña actualizada", "Ya puedes iniciar sesión.", parent=self)
            self.mostrar_login()

        self.boton("Guardar contraseña", cambiar).pack(fill="x", pady=(22, 0))
        self.boton_texto("Volver", self.mostrar_login)

    def mostrar_dashboard(self):
        self.limpiar_pantalla()
        self.titulo("Tus archivos", f"Sesión: {self.usuario_actual}")

        actions = tk.Frame(self.contenedor, bg="#17231f")
        actions.pack(fill="x", pady=(0, 14))
        tk.Button(
            actions, text="＋  Compartir archivo", command=self.seleccionar_archivo,
            cursor="hand2", bg="#d27a43", fg="#17231f", activebackground="#e59b65",
            relief="flat", bd=0, font=("Segoe UI", 10, "bold"), padx=14, pady=10
        ).pack(side="left")
        tk.Button(
            actions, text="Premium · $3/mes", command=self.mostrar_premium,
            cursor="hand2", bg="#31443b", fg="#f4f2e9", activebackground="#42574b",
            relief="flat", bd=0, font=("Segoe UI", 10, "bold"), padx=14, pady=10
        ).pack(side="right")

        table_frame = tk.Frame(self.contenedor, bg="#17231f")
        table_frame.pack(fill="both", expand=True)
        columns = ("name", "size", "expires")
        table = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
        table.heading("name", text="Archivo")
        table.heading("size", text="Tamaño")
        table.heading("expires", text="Caduca")
        table.column("name", width=330, anchor="w")
        table.column("size", width=100, anchor="e")
        table.column("expires", width=130, anchor="center")
        table.pack(fill="both", expand=True)
        for share in self.database.list_shares(self.usuario_actual):
            table.insert(
                "", "end", iid=share["code"],
                values=(share["file_name"], format_size(share["file_size"]),
                        time.strftime("%d/%m/%Y", time.localtime(share["expires_at"])))
            )

        controls = tk.Frame(self.contenedor, bg="#17231f")
        controls.pack(fill="x", pady=(12, 0))

        def copiar_enlace():
            selection = table.selection()
            if not selection:
                messagebox.showinfo("Selecciona un archivo", "Elige primero un archivo de la lista.", parent=self)
                return
            link = f"http://{self.ip_local}:{SERVER_PORT}/s/{selection[0]}"
            self.clipboard_clear()
            self.clipboard_append(link)
            messagebox.showinfo(
                "Enlace copiado", f"{link}\n\nTu amigo podrá abrirlo desde la misma red Wi-Fi.", parent=self
            )

        def eliminar_enlace():
            selection = table.selection()
            if not selection:
                messagebox.showinfo("Selecciona un archivo", "Elige primero un archivo de la lista.", parent=self)
                return
            if messagebox.askyesno(
                "Eliminar enlace", "El enlace dejará de funcionar. El archivo original no se borrará.", parent=self
            ):
                self.database.delete_share(self.usuario_actual, selection[0])
                table.delete(selection[0])

        tk.Button(
            controls, text="Copiar enlace", command=copiar_enlace, cursor="hand2",
            bg="#92c6ae", fg="#17231f", relief="flat", bd=0,
            font=("Segoe UI", 9, "bold"), padx=12, pady=8
        ).pack(side="left")
        tk.Button(
            controls, text="Eliminar enlace", command=eliminar_enlace, cursor="hand2",
            bg="#31443b", fg="#f4f2e9", relief="flat", bd=0,
            font=("Segoe UI", 9), padx=12, pady=8
        ).pack(side="left", padx=(8, 0))
        tk.Button(
            controls, text="Cerrar sesión", command=self.mostrar_login, cursor="hand2",
            bg="#17231f", fg="#b5c3b8", relief="flat", bd=0,
            font=("Segoe UI", 9), padx=12, pady=8
        ).pack(side="right")

        network_note = (
            f"Servidor activo en {self.ip_local}:{SERVER_PORT}. Mantén la aplicación y el ordenador encendidos.\n"
            "Los enlaces gratuitos caducan en 7 días. El archivo original no se copia ni se borra."
        )
        if self.error_servidor:
            network_note = f"No se pudo iniciar el servidor: {self.error_servidor}"
        tk.Label(
            self.contenedor, text=network_note, bg="#17231f", fg="#b5c3b8",
            font=("Segoe UI", 9), justify="left", wraplength=640
        ).pack(anchor="w", pady=(16, 0))

    def seleccionar_archivo(self):
        if self.error_servidor:
            messagebox.showerror("Servidor no disponible", self.error_servidor, parent=self)
            return
        file_path = filedialog.askopenfilename(title="Selecciona un archivo de hasta 50 GB")
        if not file_path:
            return
        try:
            file_size = Path(file_path).stat().st_size
        except OSError as error:
            messagebox.showerror("No se pudo leer el archivo", str(error), parent=self)
            return
        if file_size > MAX_FILE_SIZE:
            messagebox.showerror(
                "Archivo demasiado grande",
                f"El máximo es 50 GB. Este archivo ocupa {format_size(file_size)}.",
                parent=self,
            )
            return
        try:
            self.database.add_share(self.usuario_actual, file_path)
        except (OSError, sqlite3.Error) as error:
            messagebox.showerror("No se pudo crear el enlace", str(error), parent=self)
            return
        self.mostrar_dashboard()

    def mostrar_premium(self):
        messagebox.showinfo(
            "Plan Premium · $3/mes",
            "Precio propuesto: $3 USD al mes.\n\n"
            "Esta versión es una demostración local: no incluye pagos ni activa una suscripción. "
            "Para cobrar de forma segura habría que conectar una pasarela de pago y un servidor alojado.",
            parent=self,
        )


if __name__ == "__main__":
    AplicacionTransferencia().mainloop()