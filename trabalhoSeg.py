#!/usr/bin/python3 

import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.primitives import hashes, serialization  
from cryptography.hazmat.primitives.asymmetric import rsa, padding  
from cryptography.hazmat.backends import default_backend

class CrypTool:

    @staticmethod
    def hex_to_bytes(hex_str):
        try:
            return bytes.fromhex(hex_str.replace(' ','').replace('\n', '') )
        except ValueError as e:
            raise ValueError(f"Erro ao converter hexadecimal: {e}")
    
    @staticmethod
    def utf8_to_bytes(utf8_str):
        return utf8_str.encode('utf-8')
    
    @staticmethod
    def bytes_to_base64(data):
        return base64.b64decode(data).decode('utf-8')
    
    @staticmethod
    def base_64_to_bytes(b64_str):
        try:
            return base64.b64decode(b64_str)
        except Exception as e:
            raise ValueError(f"Erro ao decodificar Base64: {e}")
        
    @staticmethod
    def pad_pkcs7(data, block_size=16):
        padding_lenght = block_size - (len(data) % block_size)
        padding = bytes([padding_lenght] * padding_lenght)
        return data + padding 
    