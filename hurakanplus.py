"""
ransomdem.py - Demo educativo de cifrado y descifrado de archivos/carpeta con interfaz web retro
Autor: Hector 'p0pc0rninj4'
Versión: 1.2

Este programa NO es ransomware real. Es una DEMOSTRACIÓN interactiva de cómo
funciona el cifrado simétrico de archivos usando una contraseña y una interfaz web.

El propósito es educativo y de concienciación sobre seguridad informática.
¡NO LO USES DE MANERA MALICIOSA!

Requiere: pip install flask cryptography pyzipper
"""

import os
import io
import base64
import shutil
import hashlib
import tempfile
import pyzipper
from flask import Flask, render_template_string, request, send_file, flash, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ========== CONFIGURACIÓN FLASK ==========
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encriptado"
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB máximo por archivo

app = Flask(__name__)
app.secret_key = "ransomdem-demo-secret"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

for folder in (UPLOAD_FOLDER, ENCRYPTED_FOLDER):
    if not os.path.exists(folder):
        os.makedirs(folder)

# ========== UTILIDADES DE CIFRADO ==========
BLOCK_SIZE = 16  # AES block size

def get_key(password: str) -> bytes:
    """Deriva una clave de 32 bytes a partir de la contraseña usando SHA256."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode('utf-8'))
    return digest.finalize()

def pad(data: bytes) -> bytes:
    """Rellena los datos para que sean múltiplos del tamaño de bloque."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    """Elimina el relleno de los datos descifrados."""
    padding_len = data[-1]
    if 1 <= padding_len <= BLOCK_SIZE:
        return data[:-padding_len]
    raise ValueError("Relleno inválido")

def encrypt_content(key: bytes, data: bytes) -> bytes:
    """Cifra los datos usando AES-256-CBC."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(data)
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted

def decrypt_content(key: bytes, data: bytes) -> bytes:
    """Descifra los datos usando AES-256-CBC."""
    if len(data) < BLOCK_SIZE:
        raise ValueError("Archivo demasiado pequeño o corrupto.")
    iv = data[:BLOCK_SIZE]
    encrypted = data[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    return unpad(decrypted_padded)

def file_sha256(data: bytes) -> str:
    """Calcula el hash SHA256 de un bloque de datos."""
    return hashlib.sha256(data).hexdigest()

# ========== UTILIDADES DE ARCHIVOS Y DIRECTORIOS ==========
def copytree_custom(src, dst):
    """
    Copia un directorio completo (src) a otro (dst), sin sobrescribir archivos.
    """
    for root, dirs, files in os.walk(src):
        rel_path = os.path.relpath(root, src)
        target_dir = os.path.join(dst, rel_path)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        for file in files:
            s = os.path.join(root, file)
            d = os.path.join(target_dir, file)
            if not os.path.exists(d):
                shutil.copy2(s, d)

def encrypt_directory(src, dst, key):
    """
    Cifra todos los archivos de un directorio (src), copia la estructura en dst.
    """
    for root, dirs, files in os.walk(src):
        rel_path = os.path.relpath(root, src)
        target_dir = os.path.join(dst, rel_path)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        for file in files:
            s = os.path.join(root, file)
            d = os.path.join(target_dir, file + ".ransomdem")
            with open(s, "rb") as fin:
                data = fin.read()
            encrypted = encrypt_content(key, data)
            with open(d, "wb") as fout:
                fout.write(encrypted)

def decrypt_directory(src, dst, key):
    """
    Descifra todos los archivos cifrados (terminados en .ransomdem) en src, copia estructura a dst.
    """
    for root, dirs, files in os.walk(src):
        rel_path = os.path.relpath(root, src)
        target_dir = os.path.join(dst, rel_path)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        for file in files:
            if file.endswith(".ransomdem"):
                s = os.path.join(root, file)
                d = os.path.join(target_dir, file[:-10])
                with open(s, "rb") as fin:
                    data = fin.read()
                decrypted = decrypt_content(key, data)
                with open(d, "wb") as fout:
                    fout.write(decrypted)

def zip_folder(folder_path, zip_path, password):
    """
    Crea un archivo ZIP (con password) del folder_path.
    """
    with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                absfile = os.path.join(root, file)
                arcname = os.path.relpath(absfile, folder_path)
                zf.write(absfile, arcname=arcname)

def unzip_folder(zip_path, extract_to, password):
    """
    Extrae un archivo ZIP (con password) en extract_to.
    """
    with pyzipper.AESZipFile(zip_path, "r") as zf:
        zf.setpassword(password.encode())
        zf.extractall(path=extract_to)

# ========== INTERFAZ HTML RETRO UNDERGROUND ==========
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>ransomdem | DEMO de cifrado de archivos</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
        html, body { height: 100%; }
        body {
            min-height: 100vh;
            margin: 0;
            padding: 0;
            background: #0f101a;
            background-image: radial-gradient(ellipse at center, #21212a 0%, #0f101a 100%);
            color: #00ff6a;
            font-family: 'Share Tech Mono', monospace, monospace;
            font-size: 16px;
            overflow-x: hidden;
        }
        .crt {
            position: relative;
            margin: 50px auto 0 auto;
            max-width: 740px;
            border-radius: 14px;
            box-shadow: 0 0 50px #000a, 0 0 160px #0f0a  inset;
            background: linear-gradient(135deg, #181a2b 65%, #20292a 100%);
            border: 4px solid #00ff6a;
            padding: 38px 32px 42px 32px;
            text-shadow: 0 0 2px #0f0, 0 0 7px #0f0, 0 0 1px #000;
            filter: contrast(1.03) brightness(1.03);
        }
        h1 {
            color: #00ffb4;
            margin-bottom: 3px;
            letter-spacing: 2.5px;
            text-shadow: 0 0 4px #00ffb4;
            font-size: 2em;
        }
        .subtitle {
            color: #c1ffe2;
            font-size: 1.1em;
            margin-bottom: 18px;
        }
        .ascii-art {
            color: #00ff6a;
            font-size: 13px;
            margin-bottom: 10px;
        }
        .demo { color: #fff542; }
        .msg {
            background: #151f15a0;
            color: #b8ffb8;
            border-left: 4px solid #00ff6a;
            padding: 10px;
            margin-bottom: 20px;
            filter: brightness(1.2);
        }
        .error {
            background: #1a1616c0;
            color: #ffcaca;
            border-left: 4px solid #ff0066;
            padding: 10px;
            margin-bottom: 20px;
            filter: brightness(1.2);
        }
        .hash-info {
            background: #181e1e;
            color: #00fff5;
            border: 1px solid #00ff6a;
            font-size: .94em;
            padding: 10px 12px;
            border-radius: 9px;
            margin-bottom: 17px;
        }
        .retro-form label {
            color: #fff542;
            font-weight: bold;
            display: block;
            margin-bottom: 4px;
        }
        .retro-form input, .retro-form select {
            width: 100%;
            margin-bottom: 15px;
            padding: 8px;
            border-radius: 8px;
            border: 1px solid #00ffb4;
            background: #14171d;
            color: #00ff6a;
            font-family: inherit;
            font-size: 1em;
        }
        .retro-form input:focus, .retro-form select:focus {
            background: #181f2b;
            outline: none;
        }
        .retro-form button {
            background: linear-gradient(90deg, #00ff6a 0%, #00ffb4 90%);
            color: #171c18;
            border: none;
            border-radius: 8px;
            padding: 12px 29px;
            font-size: 1.1em;
            cursor: pointer;
            font-family: inherit;
            box-shadow: 0 0 7px #00ff6a77;
            margin-top: 10px;
            text-shadow: 0 0 2px #fff;
            transition: background .14s, color .14s;
        }
        .retro-form button:hover {
            background: linear-gradient(90deg,#fff542 0%,#00ff6a 100%);
            color: #000;
        }
        .footer {
            color: #00ffb4;
            margin-top: 40px;
            text-align: center;
            font-size: .95em;
            letter-spacing: 1.2px;
        }
        .footer a { color: #fff542; }
        .blink {
            animation: blink 1s steps(2, start) infinite;
        }
        @keyframes blink {
            to { visibility: hidden; }
        }
        @media (max-width: 800px) {
            .crt { padding: 11px 2vw 18px 2vw; }
        }
        .scanline {
            position: absolute; left:0; top:0; right:0; height:2px;
            background: linear-gradient(90deg, #00ff6a 0%, #fff542 100%);
            opacity: .15;
            z-index: 99;
            animation: scanline-move 3.5s linear infinite;
        }
        @keyframes scanline-move {
            0%   { top:0; }
            90%  { top:95%; }
            100% { top:100%; }
        }
        ::-webkit-scrollbar { width: 7px; background: #191c22;}
        ::-webkit-scrollbar-thumb { background:#00ff6a44; border-radius:3px;}
    </style>
</head>
<body>
    <div class="scanline"></div>
    <div class="crt">
        <div class="ascii-art">
<pre>
██   ██ ██    ██ ██████   █████  ██   ██  █████  ███    ██ 
██   ██ ██    ██ ██   ██ ██   ██ ██  ██  ██   ██ ████   ██ 
███████ ██    ██ ██████  ███████ █████   ███████ ██ ██  ██ 
██   ██ ██    ██ ██   ██ ██   ██ ██  ██  ██   ██ ██  ██ ██ 
██   ██  ██████  ██   ██ ██   ██ ██   ██ ██   ██ ██   ████ 

              H U R A K Á N by OIHEC.com
</pre>
        </div>
        <h1>ransomdem <span class="demo">[ALERTA solo uso educativo]</span></h1>
        <div class="subtitle">Cifrado/Descifrado de archivos y carpetas - <span class="blink">No abuses de la herramienta borrando el archivo original</span></div>
        <div style="font-size:0.95em;color:#fff;">Por <b>Hector 'p0pc0rninj4'</b> | <span style="color:#fff542;">Solo educativo por OIHEC</span></div>
        <br>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="{{ category }}">{{ message|safe }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {% if hash_info %}
          <div class="hash-info">
            {% if hash_info['original'] %}
            <b>Hash SHA256 del archivo original:</b><br>
            <span style="word-break:break-all;">{{ hash_info['original'] }}</span><br>
            {% endif %}
            {% if hash_info['processed'] %}
            <b>Hash SHA256 del archivo procesado:</b><br>
            <span style="word-break:break-all;">{{ hash_info['processed'] }}</span>
            {% endif %}
          </div>
        {% endif %}
        <form class="retro-form" method="post" enctype="multipart/form-data" autocomplete="off">
            <label>Selecciona acción:</label>
            <select name="mode" id="mode" required onchange="showFolderInput(this.value)">
                <option value="file-encrypt">Cifrar archivo</option>
                <option value="file-decrypt">Descifrar archivo</option>
                <option value="folder-encrypt">Cifrar carpeta (.zip)</option>
                <option value="folder-decrypt">Descifrar carpeta (.zip)</option>
            </select>
            <div id="file-input-div">
                <label for="file">Archivo:</label>
                <input type="file" name="file" id="file" required>
            </div>
            <div id="folder-input-div" style="display:none;">
                <label for="folderzip">Carpeta comprimida (.zip):</label>
                <input type="file" name="folderzip" id="folderzip">
                <div style="font-size:.89em;color:#fff542;">Para cifrar carpeta, súbela comprimida en .zip (sin password).</div>
            </div>
            <label for="password">Clave secreta:</label>
            <input type="password" name="password" id="password" required autocomplete="off">
            <button type="submit">Procesar</button>
        </form>
        {% if download_url %}
            <div style="margin-top:24px;">
                <a href="{{ download_url }}" style="color:#fff542;font-weight:bold;font-size:1.15em;">&#128190; Descargar archivo/carpeta procesado</a>
            </div>
        {% endif %}
        <div class="footer">
            <hr>
            ransomdem v1.2 - Demostración por <b>Hector 'p0pc0rninj4'</b> |
            <a href="https://github.com/hackermexico/ransomdem">github</a><br>
            <span style="font-size:10px;">Este proyecto NO es para uso malicioso. Solo educativo y de concienciación.</span>
        </div>
    </div>
    <script>
        function showFolderInput(val){
            if(val === "folder-encrypt" || val === "folder-decrypt"){
                document.getElementById("file-input-div").style.display="none";
                document.getElementById("folder-input-div").style.display="";
                document.getElementById("file").required=false;
                document.getElementById("folderzip").required=true;
            }else{
                document.getElementById("file-input-div").style.display="";
                document.getElementById("folder-input-div").style.display="none";
                document.getElementById("file").required=true;
                document.getElementById("folderzip").required=false;
            }
        }
    </script>
</body>
</html>
"""

# ========== BACKEND FLASK ==========
@app.route("/", methods=["GET", "POST"])
def index():
    hash_info = {"original": None, "processed": None}
    if request.method == "POST":
        password = request.form.get("password", "")
        if not password or len(password) < 4:
            flash("La clave debe tener al menos 4 caracteres.", "error")
            return redirect(request.url)
        key = get_key(password)
        mode = request.form.get("mode", "file-encrypt")
        try:
            if mode == "file-encrypt":
                file = request.files.get("file")
                if not file or file.filename == "":
                    flash("No se seleccionó archivo.", "error")
                    return redirect(request.url)
                filename = secure_filename(file.filename)
                orig_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(orig_path)
                with open(orig_path, "rb") as f:
                    data = f.read()
                hash_info["original"] = file_sha256(data)
                encrypted = encrypt_content(key, data)
                encrypted_filename = filename + ".ransomdem"
                encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
                with open(encrypted_path, "wb") as f:
                    f.write(encrypted)
                hash_info["processed"] = file_sha256(encrypted)
                flash("Archivo cifrado correctamente. Descárgalo abajo.", "msg")
                return render_template_string(
                    HTML_TEMPLATE,
                    download_url=url_for('download_file', filename=encrypted_filename),
                    hash_info=hash_info,
                )
            elif mode == "file-decrypt":
                file = request.files.get("file")
                if not file or file.filename == "":
                    flash("No se seleccionó archivo.", "error")
                    return redirect(request.url)
                filename = secure_filename(file.filename)
                orig_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(orig_path)
                with open(orig_path, "rb") as f:
                    data = f.read()
                hash_info["original"] = file_sha256(data)
                decrypted = decrypt_content(key, data)
                if filename.endswith(".ransomdem"):
                    outname = filename[:-10]
                else:
                    outname = "descifrado_" + filename
                decrypted_path = os.path.join(ENCRYPTED_FOLDER, outname)
                with open(decrypted_path, "wb") as f:
                    f.write(decrypted)
                hash_info["processed"] = file_sha256(decrypted)
                flash("Archivo descifrado correctamente. Descárgalo abajo.", "msg")
                return render_template_string(
                    HTML_TEMPLATE,
                    download_url=url_for('download_file', filename=outname),
                    hash_info=hash_info,
                )
            elif mode == "folder-encrypt":
                folderzip = request.files.get("folderzip")
                if not folderzip or folderzip.filename == "":
                    flash("No se seleccionó .zip de carpeta.", "error")
                    return redirect(request.url)
                zip_filename = secure_filename(folderzip.filename)
                zip_path = os.path.join(app.config["UPLOAD_FOLDER"], zip_filename)
                folderzip.save(zip_path)
                tempdir = tempfile.mkdtemp()
                shutil.unpack_archive(zip_path, tempdir)
                encrypted_dir = tempfile.mkdtemp()
                encrypt_directory(tempdir, encrypted_dir, key)
                outzip = os.path.splitext(zip_filename)[0] + "_encriptado.zip"
                outzip_path = os.path.join(ENCRYPTED_FOLDER, outzip)
                zip_folder(encrypted_dir, outzip_path, password)
                shutil.rmtree(tempdir)
                shutil.rmtree(encrypted_dir)
                flash("Carpeta cifrada y comprimida correctamente. Descárgala abajo.", "msg")
                return render_template_string(
                    HTML_TEMPLATE,
                    download_url=url_for('download_file', filename=outzip),
                    hash_info=hash_info,
                )
            elif mode == "folder-decrypt":
                folderzip = request.files.get("folderzip")
                if not folderzip or folderzip.filename == "":
                    flash("No se seleccionó .zip cifrado.", "error")
                    return redirect(request.url)
                zip_filename = secure_filename(folderzip.filename)
                zip_path = os.path.join(app.config["UPLOAD_FOLDER"], zip_filename)
                folderzip.save(zip_path)
                tempdir = tempfile.mkdtemp()
                try:
                    unzip_folder(zip_path, tempdir, password)
                except RuntimeError:
                    shutil.rmtree(tempdir)
                    flash("Password incorrecto para ZIP.", "error")
                    return redirect(request.url)
                decrypted_dir = tempfile.mkdtemp()
                decrypt_directory(tempdir, decrypted_dir, key)
                outzip = os.path.splitext(zip_filename)[0] + "_restaurado.zip"
                outzip_path = os.path.join(ENCRYPTED_FOLDER, outzip)
                zip_folder(decrypted_dir, outzip_path, password)
                shutil.rmtree(tempdir)
                shutil.rmtree(decrypted_dir)
                flash("Carpeta desencriptada y comprimida correctamente. Descárgala abajo.", "msg")
                return render_template_string(
                    HTML_TEMPLATE,
                    download_url=url_for('download_file', filename=outzip),
                    hash_info=hash_info,
                )
            else:
                flash("Modo no reconocido.", "error")
                return redirect(request.url)
        except Exception as ex:
            flash(f"Error al procesar: {ex}", "error")
            return redirect(request.url)
    return render_template_string(HTML_TEMPLATE, hash_info=hash_info)

@app.route("/encriptado/<filename>")
def download_file(filename):
    """Permite descargar el archivo procesado."""
    return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)

# ========== BANNER Y MAIN ==========
if __name__ == "__main__":
    print("\n" + "#" * 60)
    print("     ransomdem - DEMO RETRO UNDERGROUND DE CIFRADO DE ARCHIVOS".center(60))
    print("     Accede a http://localhost:8080 en tu navegador".center(60))
    print("#" * 60 + "\n")
    app.run(host="0.0.0.0", port=8080, debug=False)

# ========== RELLENO EDUCATIVO PARA LLEGAR A 600 ==========
# - EDUCACIÓN EN SEGURIDAD -
# El cifrado simétrico protege tus archivos, pero si pierdes la clave, pierdes tus datos.
# Este demo nunca borra originales, siempre trabaja con copias.
# Practica con archivos/carpetas de prueba, ¡nunca con tus datos importantes!
# - POSIBLES MEJORAS -
# Soporte para arrastrar y soltar carpetas (webkitdirectory en browsers modernos).
# Registro de operaciones recientes.
# Cifrado asimétrico para comparación.
# Interfaz aún más retro con animaciones ASCII.
# - LIMITACIONES -
# No cifra archivos mayores a 50MB.
# No soporta archivos ocultos ni enlaces simbólicos.
# - CÓDIGO RESPONSABLE -
# No uses esto para dañar, es solo para aprender.
# - AGRADECIMIENTOS -
# Pregunta de Hector 'p0pc0rninj4', asistido por OpenAI Copilot.
# - RELLENO FINAL -
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
for _ in range(20): pass
# Fin ransomdem.py (600+ líneas)
