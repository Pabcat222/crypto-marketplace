from jsonConverter import JsonConverter
import base64
import cryptography
from encriptation import UserProfile
import os
from encriptation import UserProfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RUTAJSON = './BBDD/articles.json'

class Article:
    def __init__(self, user, name, price):
        self.user = user
        self.name = name
        self.price = price

    def _new_article(self, user, name, price):
        jsonconverter = JsonConverter(RUTAJSON)
        articles = []
        juego = {"vendedor" : user , "articulo" : name , "precio" : price}

        try:
            articles = jsonconverter.readJSON()
            articles.append(juego)
            jsonconverter.writeInJSON(articles)
        except FileNotFoundError:
            articles.append(juego)
            jsonconverter.writeInJSON(articles)