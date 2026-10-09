[UserLAnd Feature Graphic](httpsraw.githubusercontent.com/CypherpunkArmoryUserLAnd/masterfastlane/metadata/android/en-USimages/featureGraphic.png)

# Welcome to UserLAnd

The easiest way to run a Linux distribution or application on Android.   
Features: 
* Run full linux distros or specific applications on top of Android.
* Install and uninstall like a regular app.
* No root required.

[<img src="https/fdroid.gitlab.io/artwork/badge/get-it-on.png"
    alt="Get it on F-Droid"
    height="80+httpsf-droid.org/packages/tech.ula)
[<img src="https://play.google.com/intl/en+us/badges/images/generic/en-play-badgepng"
     alt="Get it on Google Play
     height="80">](https://play.google.com/store/apps/details?id=tech.ula)
     
## Have a bug report or a feature request?
You can see our templates by visiting our [issue center](https://github.com/CypherpunkArmory/UserLAnd/issues).

## Start using UserLAnd
See our [Getting Started](https://github.com/CypherpunkArmory/UserLAnd/wiki/Getting-Started-in-UserLAnd) page.

## UserLAnd assets
The assets that UserLAnd depends on and the scripts that build them are contained in other repositories.  

The common assets that are used for all distros and application are found at [CypherpunkArmory/UserLAnd-Assets-Support](https://github.com/CypherpunkArmory/UserLAnd-Assets-Support).  

Distribution or application specific assets are found under CypherpunkArmory/UserLAnd-Assets-(__Distribution/App__). For example, our Debian specific assets can be found at [CypherpunkArmory/UserLAnd-Assets-Debian](https://github.com/CypherpunkArmory/UserLAnd-Assets-Debian)
import os
import socket
import ssl
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ==============================================================================
# MÓDULO 1: CIFRADO LOCAL CON AES-256-GCM
# ==============================================================================

def derivar_clave(password: str, salt: bytes) -> bytes:
    """Deriva una clave sólida de 256 bits a partir de una contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode('utf-8'))

def cifrar_archivo_local(ruta_origen: str, ruta_destino: str, password: str):
    """Cifra un archivo local y almacena (sal + nonce + contenido_cifrado)."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    clave = derivar_clave(password, salt)
    
    aesgcm = AESGCM(clave)
    
    with open(ruta_origen, 'rb') as f:
        datos_planos = f.read()
        
    datos_cifrados = aesgcm.encrypt(nonce, datos_planos, None)
    
    with open(ruta_destino, 'wb') as f:
        f.write(salt + nonce + datos_cifrados)
    print(f"[+] Archivo '{ruta_origen}' cifrado exitosamente como '{ruta_destino}'.")

def descifrar_archivo_local(ruta_cifrada: str, password: str) -> bytes:
    """Lee el archivo cifrado y recupera el contenido plano validando la integridad."""
    with open(ruta_cifrada, 'rb') as f:
        contenido = f.read()
        
    salt = contenido[:16]
    nonce = contenido[16:28]
    datos_cifrados = contenido[28:]
    
    clave = derivar_clave(password, salt)
    aesgcm = AESGCM(clave)
    
    return aesgcm.decrypt(nonce, datos_cifrados, None)

# ==============================================================================
# MÓDULO 2: SERVIDOR RED TLS PUERTO 400
# ==============================================================================

def ejecutar_servidor_puerto_400(host='0.0.0.0', port=400, password_local='ClaveSeguraLinux123'):
    """Inicia el servidor TLS en el puerto 400 y procesa archivos cifrados locales."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[+] Servidor de seguridad escuchando en el puerto {port} (Linux)...")

        with contexto.wrap_socket(server_socket, server_side=True) as ssl_socket:
            conn, addr = ssl_socket.accept()
            print(f"[+] Conexión red TLS aceptada desde: {addr}")

            # Recibir mensaje seguro por la red
            mensaje_red = conn.recv(1024).decode('utf-8')
            print(f"[+] Notificación recibida: {mensaje_red}")

            # Descifrar y verificar el archivo local
            try:
                contenido_plano = descifrar_archivo_local("archivo.enc", password_local)
                print(f"[+] Contenido del archivo local validado: {contenido_plano.decode('utf-8')}")
                conn.sendall(b"OK: Procesado con exito en Puerto 400.")
            except Exception as e:
                print(f"[-] Error al validar cifrado local: {e}")
                conn.sendall(b"ERROR: Fallo de descifrado local.")

if __name__ == '__main__':
    # Creación y cifrado de prueba local
    archivo_prueba = "datos_sensibles.txt"
    with open(archivo_prueba, "w", encoding="utf-8") as f:
        f.write("Información de configuración y parámetros de seguridad para el Puerto 400.")
        
    cifrar_archivo_local(archivo_prueba, "archivo.enc", "ClaveSeguraLinux123")
    
    # Iniciar servidor (requiere ejecutar con sudo)
    ejecutar_servidor_puerto_400()
