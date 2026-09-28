import json
import os

class JsonConverter:
    def __init__(self, file):
        self.file = file


    def writeInJSON(self, objectToWrite):
        try:
            with open(self.file, "w", newline='') as outfile:
                json.dump(objectToWrite, outfile, indent = 4)
        except FileNotFoundError:
            self.writeInJSON(self)
        
    def readJSON(self):
        if not os.path.isfile(self.file):
            raise FileNotFoundError(f"El archivo {self.file} no existe.")
        
        if os.path.getsize(self.file) == 0:
            raise ValueError("El archivo JSON está vacío.")
        
        try:
            with open(self.file, 'r') as file:
                jsonObject = json.load(file)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error al decodificar JSON: {e}")
        
        return jsonObject
    