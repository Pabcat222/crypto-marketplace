# Domivat: marketplace cliente-servidor con criptografía aplicada

Práctica de la asignatura de **Criptografía** (Grado en Ingeniería Informática, UC3M,
curso 2024/25), hecha en pareja por Iván Flores López y Pablo Navarro Hurtado
([@Pabcat222](https://github.com/Pabcat222)).

Un marketplace de compraventa entre particulares por terminal: los usuarios se registran en
una sucursal (Madrid o Cuenca), publican artículos, consultan los de otros y abren una
conversación cifrada con el vendedor. El objetivo de la práctica era aplicar las primitivas
criptográficas de la asignatura con la biblioteca `cryptography` de Python.

## Qué se implementó

| Mecanismo | Cómo |
|---|---|
| **Almacenamiento de contraseñas** | PBKDF2-HMAC-SHA256 (480 000 iteraciones) con sal aleatoria por usuario |
| **Autenticación en dos pasos** | TOTP (RFC 6238) con `pyotp`: el registro muestra un QR para Google/Microsoft Authenticator |
| **Cifrado de las conversaciones** | Clave simétrica (Fernet) nueva por conversación, envuelta con RSA-OAEP (SHA-256) |
| **Integridad de la clave de sesión** | HMAC-SHA256 de la clave simétrica, firmado con RSA-PSS |
| **Infraestructura de clave pública** | Jerarquía X.509 propia: raíz *Domivat ES* → autoridades intermedias de Madrid y Cuenca → certificado de cada usuario firmado por la de su sucursal; el cliente verifica la cadena firma a firma |
| **Comunicación** | Sockets TCP con un hilo por cliente en el servidor |

## Estructura

```
server.py          servidor TCP: usuarios, artículos, CA raíz y emisión de certificados
madrid.py          autoridad intermedia de la sucursal de Madrid
cuenca.py          autoridad intermedia de la sucursal de Cuenca
client.py          cliente de terminal: registro, login, artículos, conversaciones cifradas
authentication.py  login y segundo factor TOTP
encriptation.py    perfil de usuario y derivación de la contraseña con PBKDF2
article.py         modelo de artículo
jsonConverter.py   persistencia en JSON
claves/  BBDD/     se rellenan al ejecutar (claves RSA, certificados y datos)
```

## Ejecución

```bash
pip install -r requirements.txt
python server.py          # genera las claves y la jerarquía de certificados la primera vez
python client.py          # en otra terminal, uno por usuario
```

## Limitaciones conocidas

Es una práctica académica y no un diseño listo para producción:

- Todas las entidades (servidor, autoridades y usuarios) se simulan en la misma máquina y
  comparten el directorio `claves/`, así que las claves privadas no están aisladas entre sí.
- La verificación de la cadena de certificados en el cliente (`verificate_client_cert`)
  está implementada, pero quedó desactivada al iniciar la conversación en la última
  versión entregada.
- Las claves privadas se guardan en PEM sin cifrar.
