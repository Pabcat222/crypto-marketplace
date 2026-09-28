import base64
from onetimepass import valid_totp
from jsonConverter import JsonConverter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode
import pyotp
import tkinter as tk
from PIL import Image, ImageTk

RUTAJSON = './BBDD/users.json'
class Auth:

    def authenticate(self, email):
        print('En unos segundos se abrira una ventana con el qr para la autenticación en 2 pasos')
        authenticated = False
        secret = pyotp.random_base32()
        # Crear una URL para el código QR
        otp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name='Domivat')

        # Generar el código QR
        qr = qrcode.make(otp_auth_url)
        qr.save("authenticator_qr.png")

        # Crear la ventana de tkinter
        root = tk.Tk()
        root.title("Código QR para Microsoft Authenticator")

        # Cargar la imagen del código QR
        qr_image = Image.open("authenticator_qr.png")
        qr_photo = ImageTk.PhotoImage(qr_image)

        # Crear un widget Label para mostrar la imagen
        label = tk.Label(root, image=qr_photo)
        label.pack(padx=20, pady=20)

        # Mostrar la ventana
        root.mainloop()
        while not authenticated:
            otp = int(input('Introduce la clave otp para autenticarte: '))
            correct = valid_totp(otp, secret)
            if correct:
                print('otp correcto, Autenticación finalizada!')
                authenticated = True
            elif not correct:
                print('otp incorrecto, por favor inténtelo de nuevo.')


    def login(self, username, pwd):
        jsonConverter = JsonConverter(RUTAJSON)
        users = jsonConverter.readJSON()
        for user in users:
            if username == user['username']:
                pwd_2 = base64.urlsafe_b64decode(user['password'])
                salt_2 = base64.urlsafe_b64decode(user['salt'])
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt_2,
                    iterations=480000
                )
                token = kdf.derive(bytes(pwd, 'utf-8'))
                if pwd_2 == token:
                    return user
        return ''