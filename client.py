import datetime
from cryptography.hazmat.primitives import hashes, hmac
import json
import os
import re
import socket
import threading
import time
from article import Article
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from authentication import Auth
from jsonConverter import JsonConverter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
import getpass
from cryptography import x509
from cryptography.x509.oid import NameOID
from madrid import MadridServer

# Configuración del cliente
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
RUTAJSON = './BBDD/users.json'
RUTAKEY = './BBDD/encryption.key'
RUTAJSON_MSGS = './BBDD/messages.json'
RUTAJSON_ENC_SYMETRIC_KEY = './BBDD/encrypted_symetric_key.json'
RUTACHAINCERTIFICADOS = './BBDD/certificados_chains.json'
private_key = ''
receiver_public_key = ''
receiver_username = ''
RESPUESTARECIBIDA = False
loggedUser = ''
articles = []
json_msg = JsonConverter(RUTAJSON_MSGS)
json_enc_symetric_key = JsonConverter(RUTAJSON_ENC_SYMETRIC_KEY)
json_hash_sym_key = JsonConverter('./BBDD/hash_sym_key.json')
jsonCertificadosChain = JsonConverter(RUTACHAINCERTIFICADOS)
json_users = JsonConverter(RUTAJSON)

cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    cliente.connect((SERVER_HOST, SERVER_PORT))
except socket.error as e:
    print(f"Error al conectar con el servidor: {e}")
    exit(1)
loginCorrecto = False
conexionEstablecida = False

# Verificar que el certificado del cliente es válido
def verificate_client_cert(username, sucursal):
    j = jsonCertificadosChain.readJSON()
    for i in j: 
        if i['username'] == username:
            cert_1 = (i['cert_1'])
            cert_2 = (i['cert_2'])
            cert_3 = (i['cert_3'])
            
            with open(f'./BBDD/CSR/{username}_cert.pem', "rb") as certificado_cliente:
                cert_data = certificado_cliente.read()
                if cert_1 == cert_data.hex():
                    print(f'El certificado de {username} es correcto')
                cert_1_com = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Leer y verificar el certificado de la sucursal
            with open(f'./BBDD/CSR/{sucursal}_cert.pem', "rb") as certificado_sucursal:
                cert_data = certificado_sucursal.read()
                if cert_2 == cert_data.hex():
                    print(f'El certificado de {sucursal} es correcto')
                cert_2_com = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Leer y verificar el certificado raíz
            with open('./BBDD/CSR/espana_root_cert.pem', "rb") as certificado_root:
                cert_data = certificado_root.read()
                if cert_3 == cert_data.hex():
                    print(f'El certificado de espana es correcto')
                cert_3_com = x509.load_pem_x509_certificate(cert_data, default_backend())



            try:
                cert_1_com.public_key().verify(
                    cert_1_com.signature,
                    cert_1_com.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_1_com.signature_hash_algorithm
                )
                cert_2_com.public_key().verify(
                    cert_2_com.signature,
                    cert_2_com.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_2_com.signature_hash_algorithm
                )
                cert_3_com.public_key().verify(
                    cert_3_com.signature,
                    cert_3_com.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_3_com.signature_hash_algorithm
                )
            except Exception as e:
                return f'Error en la verificación de la firma: {e}'

            cert_1_com.issuer == cert_2_com.subject
            cert_2_com.issuer == cert_3_com.subject
            now = datetime.datetime.now(datetime.timezone.utc)
            if cert_1_com.not_valid_before < now < cert_1_com.not_valid_after:
                print ('El certificado del cliente es válido')
            else:
                print ('El certificado del cliente no es válido')

# Función para hashear la clave simétrica
def hashear_sym_key(sym_key):
    h = hmac.HMAC(sym_key, hashes.SHA256())
    h.update(b"message to hash")
    hash_sym_key = h.finalize()
    return hash_sym_key

# Función para encriptar el hash de la clave simétrica
def encryptear_hash_sym_key(hash_sym_key, private_key):
    encrypted_hash_sym_key = private_key.sign(
    hash_sym_key,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
    return encrypted_hash_sym_key


def decrypt_msg_public_key(enc_sym_key, private_key_receiver):
   print("clave privada del receptor:" + '\n')
   print(private_key_receiver)
   print("clave simétrica encriptada en bytes:" + '\n')
   print (enc_sym_key)
   msg_sin_public_key = private_key_receiver.decrypt(
                      bytes.fromhex(enc_sym_key), 
                      padding.OAEP(
                      mgf=padding.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(),
                      label=None))
   return msg_sin_public_key

def initialize_json(file_path):
    with open(file_path, 'w') as f:
        json.dump([], f)
        
def encript_conv():
        # Genero una clave simétrica para la conversación
        key = Fernet.generate_key()
        f = Fernet(key)
        # Hacemos el hash de la clave simétrica
        hash_sym_key = hashear_sym_key(key)
        # Recojo la clave privada del servidor para encriptar el hash de la clave simétrica
        with open('claves/' + 'server' + '_clave_privada.pem', "rb") as pem_file:
            private_key_server = serialization.load_pem_private_key(pem_file.read(), None)
        hash_sym_key_encrypted = encryptear_hash_sym_key(hash_sym_key, private_key_server)
        print("hash de la clave simétrica:" + '\n')
        print ('el hash de la clave simetrica con la privada del server es:' + '\n' + hash_sym_key_encrypted.hex() + '\n')
        
        # Recojo la clave pública del servidor para encriptar pipu
        with open('claves/' + 'server' + '_clave_publica.pem', "rb") as pem_file:
            public_key_server = serialization.load_pem_public_key(pem_file.read())
        pipu_encrypted_1 = public_key_server.encrypt(
                        key, 
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                            algorithm=hashes.SHA256(), 
                            label=None
                        )
                    )
        print("clave simetrica firmada con la publica del server:")
        print(hash_sym_key_encrypted, len(hash_sym_key_encrypted))
        print ("hash_sym_key_encrypted: " + '\n' + hash_sym_key_encrypted.hex())
        hash_sym_key_encrypted_1 = hash_sym_key_encrypted[0:255]
        hash_sym_key_encrypted_2 = hash_sym_key_encrypted[255:]
        pipu_encrypted_2 = public_key_server.encrypt(
                        hash_sym_key_encrypted_1, 
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                            algorithm=hashes.SHA256(), 
                            label=None
                        )
                    )
        pipu_encrypted_3 = public_key_server.encrypt(
                        hash_sym_key_encrypted_2, 
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                            algorithm=hashes.SHA256(), 
                            label=None
                        )
                    )
        u = []
        u.append({"servidor": "Domivat", "usuario_1": loggedUser['username'], "usuario_2": receiver_username, "Publica server(hash clave simetrica encriptado mas la simetrica)": pipu_encrypted_1.hex() + pipu_encrypted_2.hex() + pipu_encrypted_3.hex()})
        json_hash_sym_key.writeInJSON(u)
       
        return key, f



def recibir_mensajes():
    global loginCorrecto
    global RESPUESTARECIBIDA
    global receiver_username
    mensaje = cliente.recv(4096).decode()
    print("Mensaje recibido: " + mensaje)
    if mensaje:
        if mensaje.split("º")[0] == 'Logging Succesful':
            loginCorrecto = True
            global loggedUser 
            loggedUser = json.loads(mensaje.split("º")[1])
            # global private_key
            # private_key = mensaje.split("º")[2]
            print("Login exitoso.")
            RESPUESTARECIBIDA = True
        elif mensaje == "Register Succesful":
            print("Registro exitoso.")
            RESPUESTARECIBIDA = True
        elif mensaje.split("º")[0] == 'Articles Sent':
            global articles
            articles = json.loads(mensaje.split("º")[1])
            RESPUESTARECIBIDA = True
        elif mensaje.split("º")[0] == 'CONNECTEDCLIENT':
            receiver_username = mensaje.split("º")[1]
            # global receiver_public_key
            # receiver_public_key = mensaje.split("º")[1]
            choice = input(f'{receiver_username} desea iniciar una conversacion con usted por un articulo en venta, ¿desea iniciar la conversación? [y/n].')
            if choice == "y":
                key, f = encript_conv()
                iniciarConversacionCliente(key, f)
                print(f'Conversación iniciada con {receiver_username}.')
            RESPUESTARECIBIDA = True
        elif mensaje.split("º")[0] == 'CONNECTED':
            receiver_username = mensaje.split("º")[1]
            RESPUESTARECIBIDA = True
        elif mensaje == "User not connected":
            print("El usuario no está conectado.")
            RESPUESTARECIBIDA = True




# Iniciar hilos de recepción y envío de mensajes

def iniciarConversacionAnfitrion(key, f):
    while True:
        mensaje = input(f"Inserte el mensaje para {receiver_username}:('salir' para terminar la conversacion)")
        if mensaje.lower() == "salir":
            break
        mensajeToSend = encriptarMensaje(mensaje, key, f)
        time.sleep(1)
        cliente.send((f"MSG:{receiver_username},{mensajeToSend}").encode())
        print("Enviando mensaje...")
        time.sleep(1)
        print(f"Esperando respuesta de {receiver_username}")
        cliente.recv(4096).decode()
        respuestaDesencriptada = desencrypt()
        time.sleep(1)
        print(respuestaDesencriptada)
    return

def iniciarConversacionCliente(key, f):
    #p = json_users.readJSON()
    #for l in p:
    #    if l['username'] == 'q':
    #       sucursal_receiver = l['sucursal']
    #verificate_client_cert(receiver_username, sucursal_receiver)
    while True:
        time.sleep(1)
        print(f"Esperando respuesta de {receiver_username}")
        cliente.recv(4096).decode()
        respuestaDesencriptada = desencrypt()
        time.sleep(1)
        print(respuestaDesencriptada)
        mensaje = input(f"Inserte el mensaje para {receiver_username}:('salir' para terminar la conversacion)")
        if mensaje.lower() == "salir":
            break
        mensajeToSend = encriptarMensaje(mensaje, key, f)
        time.sleep(1)
        cliente.send((f"MSG:{receiver_username},{mensajeToSend}").encode())
        time.sleep(1)
        print("Enviando mensaje...")
    return


def encriptarMensaje(mensaje, key, f):
    # Encriptación
        # Recojo la clave pública del receptor
        with open('claves/' + receiver_username + "_clave_publica.pem", "rb") as pem_file:
            public_key_receptor = serialization.load_pem_public_key(pem_file.read())
        # Recojo la clave pública del cliente
        with open('claves/' + loggedUser['username'] + "_clave_publica.pem", "rb") as pem_file:
            public_key_emisor = serialization.load_pem_public_key(pem_file.read())

        # Encripto el mensaje con la clave simétrica
        token = f.encrypt(mensaje.encode('utf-8'))
        print("mensaje encriptado:" + '\n' + token.decode('utf-8') + '\n')

        # Encripto la clave simétrica con la clave pública del receptor y lo meto al json
        encrypted_key_receptor = public_key_receptor.encrypt(
            key, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )
        p = []
        p.append({"emisor": loggedUser['username'], "receptor": receiver_username,
            "clave simetrica encriptada": encrypted_key_receptor.hex()})
        json_enc_symetric_key.writeInJSON(p)
        print("clave simétrica encriptada con la pública del vendedor:" + '\n' + encrypted_key_receptor.hex() + '\n')
        

        # Encripto la clave simétrica con la clave pública del emisor y lo meto al json
        encrypted_key_cliente = public_key_emisor.encrypt(
            key, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )

        i = json_enc_symetric_key.readJSON()
        i.append({"emisor": receiver_username, "receptor": loggedUser['username'],
                    "clave simetrica encriptada": encrypted_key_cliente.hex()})
        json_enc_symetric_key.writeInJSON(i)
        print("clave simétrica encriptada con la pública del cliente:" + '\n' + encrypted_key_cliente.hex() + '\n')

        # meto el mensaje encriptado en el json
        j = []
        j.append({"emisor": loggedUser['username'], "receptor": receiver_username, 
                            "mensaje con clave simetrica": token.hex()})
        json_msg.writeInJSON(j)
        return token
    
# Desencriptación
def desencrypt():
    c = json_msg.readJSON()
    for msg in c:
        if msg["emisor"] == loggedUser['username']:
            msg_enc = msg["mensaje con clave simetrica"]


    a = json_enc_symetric_key.readJSON()
    for convers in a:
        if convers["emisor"] == loggedUser['username']:
            sym_enc_key = convers["clave simetrica encriptada"]
            print ('La clave simetrica encriptada es: ' + '\n' + sym_enc_key)
            receptor = convers["receptor"]


    ruta_a_la_clave_privada = receptor + '_clave_privada.pem'
    with open('claves/' + ruta_a_la_clave_privada, "rb") as pem_file:
        private_key_receiver = serialization.load_pem_private_key(pem_file.read(), None)
    sym_key_sin_pu_key = decrypt_msg_public_key(sym_enc_key , private_key_receiver)
    print(sym_key_sin_pu_key)

    b = json_msg.readJSON()
    for msg in b:
        if msg["receptor"] == loggedUser['username']:
            msg_enc = msg["mensaje con clave simetrica"]


    sym_key_final = Fernet(sym_key_sin_pu_key)
    msg_desencriptado = sym_key_final.decrypt(bytes.fromhex(msg_enc))

    str_data = msg_desencriptado.decode('utf-8')
    print(str_data)
    return str_data

def main():
# Código de autenticación
    global RESPUESTARECIBIDA
    auth = Auth()
    jsonConverter = JsonConverter(RUTAJSON)
    json_msg = JsonConverter(RUTAJSON_MSGS)
    json_enc_symetric_key = JsonConverter(RUTAJSON_ENC_SYMETRIC_KEY)
    print('Bienvenido a Domivat:')
    respuesta = ''
    while respuesta != '1' and respuesta != '2':
        respuesta = input('Escoja una opción: (1) Iniciar Sesión | (2) Registrarse:\n')

    if respuesta == '1':
        while not loginCorrecto:
            username = input('Inserte usuario:\n')
            pwd = getpass.getpass('Inserte contraseña:\n')
            cliente.send(f"LOGIN:{username}, {pwd}".encode())
            
            print("Esperando respuesta del servidor...")
            recibir_mensajes()
            while not RESPUESTARECIBIDA:
                pass
            RESPUESTARECIBIDA = False
            if not loginCorrecto:
                print("Usuario o contraseña incorrectos, vuelve a intentarlo.")
        #auth.authenticate(loggedUser['email'])
        print('Sesion iniciada correctamente')
        salir = False
        while not salir:
            respuesta = input('Escoja una opción: (1) Añadir artículos a mi lista | (2) Borrar artículos de mi lista | (3) Ver artículos | (4) Ver conexiones pendientes:\n')
            if respuesta == '1':
                article = input('Introduzca el nombre del artículo:\n')
                price = input('Introduzca el precio del artículo:\n')
                #juego = {"vendedor":username "articulo":article, "precio":price}
                a = Article(username, article, price)
                a._new_article(username, article, price)
                #user['articles'].append(juego)
            # Borrar artículos de mi lista para no tenerlos en venta
            if respuesta == '2':
                article = input('Introduzca el nombre del artículo:\n')
                for juego in loggedUser['articles']:
                    if juego["articulo"] == article:
                        loggedUser['articles'].remove(juego)
            # Ver artículos en venta
            if respuesta == '3':
                cliente.send(f"GETARTICLES:{username}".encode())
                print('Esperando respuesta del servidor...')
                recibir_mensajes()
                while not RESPUESTARECIBIDA:
                    pass
                RESPUESTARECIBIDA = False
                i = 1
                for article in articles:
                    print (f'({i}) {article["articulo"]}: {article["precio"]}\n')
                    i += 1
                # Mensajería para comprar el artículo deseado
                seleccion = input('Seleccione uno para comprar (0 para salir)\n')
                if seleccion != '0':
                    article = articles[int(seleccion)-1]
                    cliente.send(("TRYCONNECT:" + article['vendedor']).encode())
                    print("Esperando respuesta del servidor...")
                    recibir_mensajes()
                    while not RESPUESTARECIBIDA:
                        pass
                    RESPUESTARECIBIDA = False
                        # global receiver_public_key
                        # receiver_public_key = mensaje.split("º")[1]
                    if receiver_username != '':
                        choice = input(f'{receiver_username} desea iniciar una conversacion con usted por un articulo en venta, ¿desea iniciar la conversación? [y/n].')
                        if choice == "y":
                            print(f'Conversación iniciada con {receiver_username}.')
                            key, f = encript_conv()
                            iniciarConversacionAnfitrion(key, f)

            if respuesta ==  '4':
                print("Esperando conexión")
                recibir_mensajes()
            
            choice = input("Desea realizar otra operación? [y/n]")
            if choice == "n":
                salir = True

    elif respuesta == '2':
        username = input('Inserte un usuario:\n')
        email = input('Inserte su correo electrónico:\n')
        pwd = input('Inserte una contraseña:\n')
        sucursal = input('Elija su sucursal (1)Madrid, (2)Cuenca:\n')
        if sucursal == '1':
            sucursal = 'madrid'
        elif sucursal == '2':
            sucursal = 'cuenca'
        #Convertimos a bytes
        # pwdCorrecta = False
        # regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$'
        # while not pwdCorrecta:
        #     pwd = getpass.getpass('Inserte una contraseña (debe tener al menos 8 caracteres, mayúsculas, minúsculas y números):\n')
        #     if re.match(regex, pwd):
        #         pwdCorrecta = True
        #     else:
        #         print("ERROR")
        # pwdMatch = False
        # while not pwdMatch:
        #     pwd2 = getpass.getpass('Confirme la contraseña')
        #     if pwd2 == pwd:
        #         pwdMatch = True
        #     else:
        #         print("ERROR, las contraseñas no coinciden")
        cliente.send(f"REGISTER:{username}, {pwd}, {email}, {sucursal}".encode())
        print("Esperando respuesta del servidor...")
        recibir_mensajes()
        while not RESPUESTARECIBIDA:
            pass
        RESPUESTARECIBIDA = False
        print("Registro exitoso.")
    

main()