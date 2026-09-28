import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



class UserProfile:
    def __init__(self, username, email, pwd, sucursal):
        self.username = username
        self.email = email
        self.salt = os.urandom(16)
        self.password = self._encrypt_password(pwd)
        self.sucursal = sucursal

    def _encrypt_password(self, pwd):
        """Método interno para encriptar la contraseña usando PBKDF2 y SHA256"""
        # Crear objeto para codificar
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000
        )
        # Generar el hash de la contraseña
        token = base64.urlsafe_b64encode(kdf.derive(pwd))
        return token.decode('utf-8')

    def get_profile(self):
        """Retorna el perfil del usuario con los datos generados"""
        return {
            "username": self.username,
            "sucursal": self.sucursal,
            "email": self.email,
            "password": self.password,
            "salt": base64.urlsafe_b64encode(self.salt).decode('utf-8'),
        }