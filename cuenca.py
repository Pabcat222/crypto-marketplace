import os
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID

# Ruta al archivo de la clave privada del servidor
nombre_file_privada = 'claves/cuenca_clave_privada.pem'
nombre_file_publica = 'claves/cuenca_clave_publica.pem'


class CuencaServer:
    def __init__(self):
        self.gen_claves = generar_claves()
        self.private_key = load_private_key()
        # self.csr = self.generate_csr()
        generate_certificate(self.private_key)


def generar_claves():
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


def generate_csr(self):
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cuenca"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Domivat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.domivat.es"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName("domivat.com"),
        ]),
        critical=False,
    # Sign the CSR with our private key.
    ).sign(self.private_key, hashes.SHA256())
    # Write our CSR out to disk.
    with open(f"./BBDD/CSR/cuenca_csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def load_private_key():
    # Cargar la clave privada del servidor cuenca
    with open(nombre_file_privada, "rb") as archivo_privado:
        clave_privada = serialization.load_pem_private_key(
            archivo_privado.read(),
            password=None,
            backend=default_backend()
        )
    return clave_privada

def generate_certificate(private_key):
    # Generate our intermediate key
    with open("claves/server_clave_privada.pem", "rb") as archivo_privado:
        root_key = serialization.load_pem_private_key(
            archivo_privado.read(),
            password=None,
            backend=default_backend()
        )
    cert_file_path = './BBDD/CSR/espana_root_cert.pem'

    # Leer el certificado desde el archivo .pem
    with open(cert_file_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        root_cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cuenca"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Domivat"),
    ])
    int_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our intermediate will be valid for ~3 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*3)
    ).add_extension(
        # Allow no further intermediates (path length 0)
        x509.BasicConstraints(ca=True, path_length=0),
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
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ),
        critical=False,
    ).sign(root_key, hashes.SHA256())

    int_cert_pem = int_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    with open(f"./BBDD/CSR/cuenca_cert.pem", "wb") as f:
        f.write(int_cert_pem)