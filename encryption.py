"""
encryption.py

Laboratorio de Cifrado y Manejo de Credenciales

En este módulo deberás implementar:

- Descifrado AES (MODE_EAX)
- Hash de contraseña con salt usando PBKDF2-HMAC-SHA256
- Verificación de contraseña usando el mismo salt

NO modificar la función encrypt_aes().
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import hmac

# ==========================================================
# AES-GCM (requiere pip install pycryptodome)
# ==========================================================

def encrypt_aes(texto, clave):
    """
    Cifra un texto usando AES en modo EAX.

    Retorna:
        texto_cifrado_hex
        nonce_hex
        tag_hex
    """

    texto_bytes = texto.encode()

    cipher = AES.new(clave, AES.MODE_EAX)

    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    return (
        texto_cifrado.hex(),
        nonce.hex(),
        tag.hex()
    )




def decrypt_aes(texto_cifrado_hex, nonce_hex, tag_hex, clave):
    

    texto_cifrado = bytes.fromhex(texto_cifrado_hex)
    nonce = bytes.fromhex(nonce_hex)
    tag = bytes.fromhex(tag_hex)

    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)

    texto_descifrado_bytes = cipher.decrypt_and_verify(texto_cifrado, tag)

    return texto_descifrado_bytes.decode()


# ==========================================================
# PASSWORD HASHING (PBKDF2 - SHA256)
# ==========================================================


def hash_password(password):
    salt = os.urandom(16)
    iterations = 200000

    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    )
    return{
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": dk.hex()
    }


def verify_password(password, stored_data):

    iterations = stored_data.get("iterations")
    salt_hex = stored_data.get("salt")
    hash_hex = stored_data.get("hash")

    salt = bytes.fromhex(salt_hex)

    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    )

    return hmac.compare_digest(dk.hex(), hash_hex)




if __name__ == "__main__":

    print("=== PRUEBA AES ===")

    texto = "Hola Mundo"
    clave = get_random_bytes(16)

    texto_cifrado, nonce, tag = encrypt_aes(texto, clave)

    print("Texto cifrado:", texto_cifrado)
    print("Nonce:", nonce)
    print("Tag:", tag)

    # Cuando implementen decrypt_aes, esto debe funcionar
    texto_descifrado = decrypt_aes(texto_cifrado, nonce, tag, clave)
    print("Texto descifrado:", texto_descifrado)


    print("\n=== PRUEBA HASH ===")

    password = "Password123!"

    # Cuando implementen hash_password:
    pwd_data = hash_password(password)
    print("Hash generado:", pwd_data)

    # Cuando implementen verify_password:
    print("Verificación correcta:",
    verify_password("Password123!", pwd_data))