import socket
import threading
import os
import json
import time
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from authentication import Auth
from encriptation import UserProfile
from jsonConverter import JsonConverter
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from madrid import MadridServer
from cuenca import CuencaServer

RUTAKEY = './BBDD/encryption.key'
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 12345
RUTAJSON = './BBDD/users.json'
RUTAARTICLES = './BBDD/articles.json'
RUTACHAINCERTIFICADOS = './BBDD/certificados_chains.json'

# Ruta al archivo de la clave privada del servidor
nombre_file_privada = 'claves/server_clave_privada.pem'
nombre_file_publica = 'claves/server_clave_publica.pem'


# Verificar si el archivo de la clave privada no existe
if not os.path.exists(nombre_file_privada):
    # El servidor debe tener una clave privada y una clave pública
    clave_privada_server = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # La clave publica sale de la clase privada
    clave_publica_server = clave_privada_server.public_key()

    # Guardar la clave privada en el archivo pem
    with open(nombre_file_privada, "wb") as archivo_privado:
        archivo_privado.write(
            clave_privada_server.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Obtener la clave pública en formato PEM
    clave_publica_pem = clave_publica_server.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar la clave pública en un archivo .pem
    with open(nombre_file_publica, "wb") as archivo_publico:
        archivo_publico.write(clave_publica_pem)

    print("Claves generadas y guardadas correctamente.")
else:
    print("Las claves ya existen. No se generaron nuevas claves.")


# Crear root del árbol de certificados
with open ('claves/server_clave_privada.pem', "rb") as archivo_privado:
    root_key = serialization.load_pem_private_key(
        archivo_privado.read(),
        password=None,
        backend=default_backend()
    )
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Europa"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Espana"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Domivat"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Domivat ES"),
])
root_cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    root_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    # Our certificate will be valid for ~10 years
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    ),
    critical=True,
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
    critical=False,
).sign(root_key, hashes.SHA256())

root_cert_pem = root_cert.public_bytes(
    encoding=serialization.Encoding.PEM
)
with open('./BBDD/CSR/espana_root_cert.pem', "wb") as certificado_server:
        certificado_server.write(root_cert_pem)

# Crear diccionario con los certificados necesarios para verificar a un cliente
def generate_client_cert_dict(username, sucursal):
    jsonCertificadosChain = JsonConverter(RUTACHAINCERTIFICADOS)
    ret = {}
    r = []
    ret['username'] = username
    cert_2_file_path = f'./BBDD/CSR/{sucursal}_cert.pem'
    cert_3_file_path = './BBDD/CSR/espana_root_cert.pem'
    with open(f'./BBDD/CSR/{username}_cert.pem', "rb") as certificado_cliente:
        cert_data = certificado_cliente.read()
        ret['cert_1'] = cert_data.hex()
    with open(cert_2_file_path, "rb") as certificado_sucursal:
        cert_data = certificado_sucursal.read()
        ret['cert_2'] = cert_data.hex()
    with open(cert_3_file_path, "rb") as certificado_root:
        cert_data = certificado_root.read()
        ret['cert_3'] = cert_data.hex()
    try:
        r = jsonCertificadosChain.readJSON()
        r.append(ret)
        jsonCertificadosChain.writeInJSON(r)
    except FileNotFoundError:
        r.append(ret)
        jsonCertificadosChain.writeInJSON(r)

madridServer = MadridServer()
cuencaServer = CuencaServer()



def initialize_json(file_path):
    with open(file_path, 'w') as f:
        json.dump([], f)


def generate_key():
    password = b"password"  
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    with open(RUTAKEY, 'wb') as key_file:
        key_file.write(salt + key)
    return key

def load_key():
    with open(RUTAKEY, 'rb') as key_file:
        data = key_file.read()
        salt = data[:16]
        key = data[16:]
    return key


# def encrypt_file(file_path, key):
#     with open(file_path, 'rb') as f:
#         data = f.read()
#     chacha = ChaCha20Poly1305(key)
#     nonce = os.urandom(12)
#     encrypted_data = chacha.encrypt(nonce, data, None)
#     with open(file_path, 'wb') as f:
#         f.write(nonce + encrypted_data)


# def decrypt_file(file_path, key):
#     try:
#         with open(file_path, 'rb') as f:
#             data = f.read()
        
#         if len(data) < 12:
#             raise ValueError("El archivo encriptado es demasiado pequeño para contener un nonce válido.")
        
#         nonce = data[:12]
#         encrypted_data = data[12:]
        
#         chacha = ChaCha20Poly1305(key)
#         decrypted_data = chacha.decrypt(nonce, encrypted_data, None)
        
#         with open(file_path, 'wb') as f:
#             f.write(decrypted_data)
        
#         print("Desencriptación exitosa.")
#     except Exception as e:
#         print(f"Error durante la desencriptación: {e}")





# Configuración del servidor

jsonConverter = JsonConverter(RUTAJSON)
jsonArticles = JsonConverter(RUTAARTICLES)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_HOST, SERVER_PORT))
server.listen(5)
auth = Auth()
print(f"Servidor escuchando en {SERVER_HOST}:{SERVER_PORT}")



if not os.path.exists(RUTAJSON):
    if not os.path.exists(RUTAJSON):
        initialize_json(RUTAJSON)
    key = generate_key()
    #encrypt_file(RUTAJSON, key)

else:
    key = load_key()
    #decrypt_file(RUTAJSON, key)


clientes = {}
direcciones = {}

def generate_client_cert(username, sucursal):
    cert_file_path = f'./BBDD/CSR/{sucursal}_cert.pem'

    # Leer el certificado desde el archivo .pem
    with open(cert_file_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        int_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    with open(f"claves/{sucursal}_clave_privada.pem", "rb") as archivo_privado2:
        int_key = serialization.load_pem_private_key(
            archivo_privado2.read(),
            password=None,
            backend=default_backend()
        )

    with open(f"claves/{username}_clave_privada.pem", "rb") as archivo_privado2:
        ee_key = serialization.load_pem_private_key(
            archivo_privado2.read(),
            password=None,
            backend=default_backend()
        )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, sucursal),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Domivat"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    ee_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        int_cert.subject
    ).public_key(
        ee_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our cert will be valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName("cryptography.io"),
            x509.DNSName("www.cryptography.io"),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            int_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    ).sign(int_key, hashes.SHA256())

    ee_cert_pem = ee_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    with open(f"./BBDD/CSR/{username}_cert.pem", "wb") as f:
        f.write(ee_cert_pem)

def manejar_cliente(cliente_socket, cliente_address):
    while True:
        try:
            mensaje = cliente_socket.recv(1024).decode()
            if mensaje:
                print(f"Mensaje recibido de {cliente_address}: {mensaje}")
                manejar_mensaje(mensaje, cliente_socket)
            else:
                cliente_socket.close()
                del clientes[cliente_socket]
                break
        except Exception as e:
            print(e)
            cliente_socket.close()
            #del clientes[cliente_socket]
            break

def manejar_mensaje(mensaje, cliente_socket):
    partes = mensaje.split(':', 1)
    if len(partes) > 1:
        comando, contenido = partes[0], partes[1]
        if comando == 'GETARTICLES':
            articles = jsonArticles.readJSON()
            articlesToSend = []
            for article in articles:
                if article['vendedor'] != contenido:
                    articlesToSend.append(article)
            articles_str = json.dumps(articlesToSend)
            #Esperamos 2 segundos para que termine de volcar el json a la variable string
            time.sleep(2)
            print(f"Articulos enviados: {articles_str}")
            cliente_socket.send(("Articles Sentº" + articles_str).encode())
        elif comando == 'TRYCONNECT':
            #Caso para comprobar que el emisor y el receptor de los mensajes estan conectados 
            usernameReceiver = contenido
            for receiver_socket, receiver_username in clientes.items():
                if receiver_username == usernameReceiver:
                    # with open(usernameReceiver + "_clave_publica.pem", "rb") as pem_file:
                    #     public_key_vendedor = serialization.load_pem_public_key(pem_file.read())
                    usernameSender = clientes[cliente_socket]
                    # with open(usernameSender + "_clave_publica.pem", "rb") as pem_file:
                    #    public_key_comprador = serialization.load_pem_public_key(pem_file.read())
                    print(f"Intentando conectar a {usernameReceiver} con {usernameSender}")
                    time.sleep(1)
                    print(f"Receptor enviado")
                    cliente_socket.send((f"CONNECTEDº{usernameReceiver}").encode())
                    time.sleep(1)
                    print(f"Emisor enviado")
                    receiver_socket.send((f"CONNECTEDCLIENTº{usernameSender}").encode())
                    return
            cliente_socket.send("User not connected".encode())
        elif comando == 'LOGIN':
            username, pwd = contenido.split(',')
            pwd = pwd.strip()
            #loginCorrecto, user = auth.login(username, pwd)
            #if loginCorrecto:
                # Si user es un diccionario, conviértelo a una cadena JSON
            user = auth.login(username, pwd)
            # with open(username + "_clave_privada.pem", "rb") as pem_file:
            #             private_key = serialization.load_pem_private_key(pem_file.read(),password=None,)
            if user == '':
                print("Login incorrecto")
                cliente_socket.send(("Login incorrecto").encode())

            user_str = json.dumps(user) if isinstance(user, dict) else user
            print(f"Login enviado")
            cliente_socket.send(("Logging Succesfulº"+ user_str).encode())
            clientes[cliente_socket] = username.strip()
        elif comando == 'LOGIN':
            username, pwd = contenido.split(',')
            pwd = pwd.strip()
            #loginCorrecto, user = auth.login(username, pwd)
            #if loginCorrecto:
                # Si user es un diccionario, conviértelo a una cadena JSON
            user = auth.login(username, pwd)
            # with open(username + "_clave_privada.pem", "rb") as pem_file:
            #             private_key = serialization.load_pem_private_key(pem_file.read(),password=None,)
            if user == '':
                print("Login incorrecto")
                cliente_socket.send(("Login incorrecto").encode())

            user_str = json.dumps(user) if isinstance(user, dict) else user
            print(f"Login enviado")
            cliente_socket.send(("Logging Succesfulº"+ user_str).encode())
            clientes[cliente_socket] = username.strip()
        elif comando == 'REGISTER':
            username, pwd, email, sucursal = contenido.split(',')
            pwd = bytes(pwd.strip(), 'utf-8')
            email = email.strip()
            sucursal = sucursal.strip()
            usuario = UserProfile(username, email, pwd, sucursal)
            profile = usuario.get_profile()
            users = []
            #decrypt_file(RUTAJSON, key)
            users = jsonConverter.readJSON()
            users.append(profile)
            jsonConverter.writeInJSON(users)
            #encrypt_file(RUTAJSON, key)

            # GENERACION DE CLAVES PUBLICA Y PRIVADA

            # Generar clave privada
            clave_privada  = rsa.generate_private_key(
                                        public_exponent=65537,
                                        key_size=4096,
                                    )

            # La clave publica sale de la clase privada
            clave_publica = clave_privada.public_key()

            # guardamos la clave privada en el archivo pem
            nombre_file = 'claves/' +username + '_clave_privada.pem'
            with open(nombre_file, "wb") as archivo_privado:
                archivo_privado.write(
                    clave_privada.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

            clave_publica_pem = clave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Guardar la clave pública en un archivo .pem
            nombre_file = 'claves/' + username + '_clave_publica.pem'
            with open(nombre_file, "wb") as archivo_publico:
                archivo_publico.write(clave_publica_pem)

            generate_client_cert(username, sucursal)
            generate_client_cert_dict(username, sucursal)

            print(f"Registro enviado")    
            cliente_socket.send("Register Succesful".encode())
        elif comando == 'MSG':
            destinatario, msg = contenido.split(',', 1)
            enviar_mensaje(destinatario.strip(), msg.strip(), cliente_socket)

def enviar_mensaje(destinatario, mensaje, cliente_socket):
    for cliente, nombre in clientes.items():
        if nombre == destinatario:
            try:
                print("Mensaje enviado")
                cliente.send((f"{clientes[cliente_socket]}º{mensaje}").encode())
            except Exception as e:
                cliente.close()
                del clientes[cliente]

while True:
    cliente_socket, cliente_address = server.accept()
    direcciones[cliente_socket] = cliente_address
    print(f"Nuevo cliente conectado: {cliente_address}")
    threading.Thread(target=manejar_cliente, args=(cliente_socket, cliente_address)).start()


