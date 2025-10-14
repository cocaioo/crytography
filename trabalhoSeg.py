#!/usr/bin/env python3
"""
Trabalho 01 - Segurança em Sistemas Computacionais
Algoritmos de Criptografia: AES e RSA
"""

import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class CryptoTool:
    """Ferramenta de criptografia com AES e RSA"""
    
    @staticmethod
    def hex_to_bytes(hex_str):
        """Converte string hexadecimal para bytes"""
        try:
            return bytes.fromhex(hex_str.replace(' ', '').replace('\n', ''))
        except ValueError as e:
            raise ValueError(f"Erro ao converter hexadecimal: {e}")
    
    @staticmethod
    def utf8_to_bytes(utf8_str):
        """Converte string UTF-8 para bytes"""
        return utf8_str.encode('utf-8')
    
    @staticmethod
    def bytes_to_hex(data):
        """Converte bytes para hexadecimal"""
        return data.hex()
    
    @staticmethod
    def bytes_to_base64(data):
        """Converte bytes para Base64"""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_to_bytes(b64_str):
        """Converte Base64 para bytes"""
        try:
            return base64.b64decode(b64_str)
        except Exception as e:
            raise ValueError(f"Erro ao decodificar Base64: {e}")
    
    @staticmethod
    def pad_pkcs7(data, block_size=16):
        """Aplica padding PKCS7"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def unpad_pkcs7(data):
        """Remove padding PKCS7"""
        if len(data) == 0:
            raise ValueError("Dados vazios para remover padding")
        padding_length = data[-1]
        if padding_length > len(data) or padding_length == 0:
            raise ValueError("Padding inválido")
        return data[:-padding_length]
    
    def aes_encrypt(self, plaintext_file, key, iv, key_size, mode, output_format, key_format, output_file):
        """
        Cifra arquivo usando AES
        
        Args:
            plaintext_file: arquivo de entrada em claro
            key: chave de cifragem
            iv: vetor de inicialização (para CBC)
            key_size: tamanho da chave (128, 192, 256)
            mode: modo de operação (ECB ou CBC)
            output_format: formato de saída (HEX ou BASE64)
            key_format: formato da chave/IV (HEX ou UTF8)
            output_file: arquivo de saída
        """
        try:
            # Ler arquivo de entrada
            with open(plaintext_file, 'rb') as f:
                plaintext = f.read()
            
            # Processar chave
            if key_format.upper() == 'HEX':
                key_bytes = self.hex_to_bytes(key)
            else:  # UTF8
                key_bytes = self.utf8_to_bytes(key)
            
            # Validar tamanho da chave
            expected_key_size = key_size // 8
            if len(key_bytes) != expected_key_size:
                raise ValueError(f"Chave deve ter {expected_key_size} bytes ({key_size} bits)")
            
            # Aplicar padding
            padded_plaintext = self.pad_pkcs7(plaintext)
            
            # Cifrar
            if mode.upper() == 'ECB':
                cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
            elif mode.upper() == 'CBC':
                # Processar IV
                if key_format.upper() == 'HEX':
                    iv_bytes = self.hex_to_bytes(iv)
                else:  # UTF8
                    iv_bytes = self.utf8_to_bytes(iv)
                
                if len(iv_bytes) != 16:
                    raise ValueError("IV deve ter 16 bytes (128 bits)")
                
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
            else:
                raise ValueError("Modo deve ser ECB ou CBC")
            
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            # Formatar saída
            if output_format.upper() == 'HEX':
                output_data = self.bytes_to_hex(ciphertext)
            else:  # BASE64
                output_data = self.bytes_to_base64(ciphertext)
            
            # Salvar arquivo
            with open(output_file, 'w') as f:
                f.write(output_data)
            
            print(f"✓ Arquivo cifrado com sucesso: {output_file}")
            
        except FileNotFoundError:
            print(f"✗ Erro: Arquivo '{plaintext_file}' não encontrado")
        except Exception as e:
            print(f"✗ Erro na cifragem: {e}")
    
    def aes_decrypt(self, ciphertext_file, key, iv, key_size, mode, input_format, key_format, output_file):
        """
        Decifra arquivo usando AES
        
        Args:
            ciphertext_file: arquivo de entrada criptografado
            key: chave de decifragem
            iv: vetor de inicialização (para CBC)
            key_size: tamanho da chave (128, 192, 256)
            mode: modo de operação (ECB ou CBC)
            input_format: formato de entrada (HEX ou BASE64)
            key_format: formato da chave/IV (HEX ou UTF8)
            output_file: arquivo de saída
        """
        try:
            # Ler arquivo de entrada
            with open(ciphertext_file, 'r') as f:
                ciphertext_str = f.read().strip()
            
            # Processar ciphertext
            if input_format.upper() == 'HEX':
                ciphertext = self.hex_to_bytes(ciphertext_str)
            else:  # BASE64
                ciphertext = self.base64_to_bytes(ciphertext_str)
            
            # Processar chave
            if key_format.upper() == 'HEX':
                key_bytes = self.hex_to_bytes(key)
            else:  # UTF8
                key_bytes = self.utf8_to_bytes(key)
            
            # Validar tamanho da chave
            expected_key_size = key_size // 8
            if len(key_bytes) != expected_key_size:
                raise ValueError(f"Chave deve ter {expected_key_size} bytes ({key_size} bits)")
            
            # Decifrar
            if mode.upper() == 'ECB':
                cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
            elif mode.upper() == 'CBC':
                # Processar IV
                if key_format.upper() == 'HEX':
                    iv_bytes = self.hex_to_bytes(iv)
                else:  # UTF8
                    iv_bytes = self.utf8_to_bytes(iv)
                
                if len(iv_bytes) != 16:
                    raise ValueError("IV deve ter 16 bytes (128 bits)")
                
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
            else:
                raise ValueError("Modo deve ser ECB ou CBC")
            
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding
            plaintext = self.unpad_pkcs7(padded_plaintext)
            
            # Salvar arquivo
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            print(f"✓ Arquivo decifrado com sucesso: {output_file}")
            
        except FileNotFoundError:
            print(f"✗ Erro: Arquivo '{ciphertext_file}' não encontrado")
        except Exception as e:
            print(f"✗ Erro na decifragem: {e}")
    
    def generate_rsa_keys(self, key_size, private_key_file, public_key_file):
        """
        Gera par de chaves RSA compatível com OpenSSL
        
        Args:
            key_size: tamanho da chave (1024 ou 2048)
            private_key_file: arquivo para salvar chave privada
            public_key_file: arquivo para salvar chave pública
        """
        try:
            if key_size not in [1024, 2048]:
                raise ValueError("Tamanho da chave deve ser 1024 ou 2048 bits")
            
            # Gerar par de chaves
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Serializar chave privada (sem senha)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serializar chave pública
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Salvar chaves
            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
            
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)
            
            print(f"✓ Chaves RSA geradas com sucesso:")
            print(f"  - Chave privada: {private_key_file}")
            print(f"  - Chave pública: {public_key_file}")
            
        except Exception as e:
            print(f"✗ Erro ao gerar chaves: {e}")
    
    def rsa_sign(self, private_key_file, plaintext_file, signature_file, sha_version, output_format):
        """
        Assina arquivo usando RSA
        
        Args:
            private_key_file: arquivo com chave privada
            plaintext_file: arquivo em claro
            signature_file: arquivo para salvar assinatura
            sha_version: versão do SHA-2 (256, 384, 512)
            output_format: formato de saída (HEX ou BASE64)
        """
        try:
            # Ler chave privada
            with open(private_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Ler arquivo em claro
            with open(plaintext_file, 'rb') as f:
                plaintext = f.read()
            
            # Selecionar algoritmo de hash
            if sha_version == 256:
                hash_algo = hashes.SHA256()
            elif sha_version == 384:
                hash_algo = hashes.SHA384()
            elif sha_version == 512:
                hash_algo = hashes.SHA512()
            else:
                raise ValueError("Versão SHA deve ser 256, 384 ou 512")
            
            # Assinar
            signature = private_key.sign(
                plaintext,
                padding.PSS(
                    mgf=padding.MGF1(hash_algo),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_algo
            )
            
            # Formatar saída
            if output_format.upper() == 'HEX':
                output_data = self.bytes_to_hex(signature)
            else:  # BASE64
                output_data = self.bytes_to_base64(signature)
            
            # Salvar assinatura
            with open(signature_file, 'w') as f:
                f.write(output_data)
            
            print(f"✓ Arquivo assinado com sucesso: {signature_file}")
            
        except FileNotFoundError as e:
            print(f"✗ Erro: Arquivo não encontrado - {e}")
        except Exception as e:
            print(f"✗ Erro ao assinar: {e}")
    
    def rsa_verify(self, public_key_file, plaintext_file, signature_file, sha_version, input_format):
        """
        Verifica assinatura RSA
        
        Args:
            public_key_file: arquivo com chave pública
            plaintext_file: arquivo em claro
            signature_file: arquivo com assinatura
            sha_version: versão do SHA-2 (256, 384, 512)
            input_format: formato da assinatura (HEX ou BASE64)
        """
        try:
            # Ler chave pública
            with open(public_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            # Ler arquivo em claro
            with open(plaintext_file, 'rb') as f:
                plaintext = f.read()
            
            # Ler assinatura
            with open(signature_file, 'r') as f:
                signature_str = f.read().strip()
            
            # Processar assinatura
            if input_format.upper() == 'HEX':
                signature = self.hex_to_bytes(signature_str)
            else:  # BASE64
                signature = self.base64_to_bytes(signature_str)
            
            # Selecionar algoritmo de hash
            if sha_version == 256:
                hash_algo = hashes.SHA256()
            elif sha_version == 384:
                hash_algo = hashes.SHA384()
            elif sha_version == 512:
                hash_algo = hashes.SHA512()
            else:
                raise ValueError("Versão SHA deve ser 256, 384 ou 512")
            
            # Verificar assinatura
            try:
                public_key.verify(
                    signature,
                    plaintext,
                    padding.PSS(
                        mgf=padding.MGF1(hash_algo),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_algo
                )
                print("✓ Assinatura VÁLIDA")
            except Exception:
                print("✗ Assinatura INVÁLIDA")
            
        except FileNotFoundError as e:
            print(f"✗ Erro: Arquivo não encontrado - {e}")
        except Exception as e:
            print(f"✗ Erro ao verificar assinatura: {e}")


def print_menu():
    """Exibe menu principal"""
    print("\n" + "="*60)
    print("  SISTEMA DE CRIPTOGRAFIA - AES E RSA")
    print("="*60)
    print("1. Cifrar arquivo (AES)")
    print("2. Decifrar arquivo (AES)")
    print("3. Gerar par de chaves RSA")
    print("4. Assinar arquivo (RSA)")
    print("5. Verificar assinatura (RSA)")
    print("0. Sair")
    print("="*60)


def get_input(prompt, valid_options=None, input_type=str):
    """Obtém entrada do usuário com validação"""
    while True:
        try:
            value = input(prompt).strip()
            if not value:
                print("✗ Entrada não pode ser vazia")
                continue
            
            if input_type == int:
                value = int(value)
            
            if valid_options and value not in valid_options:
                print(f"✗ Opção inválida. Escolha entre: {valid_options}")
                continue
            
            return value
        except ValueError:
            print(f"✗ Entrada inválida. Esperado: {input_type.__name__}")
        except KeyboardInterrupt:
            print("\n✗ Operação cancelada")
            return None


def main():
    """Função principal"""
    crypto = CryptoTool()
    
    while True:
        print_menu()
        choice = input("Escolha uma opção: ").strip()
        
        try:
            if choice == '1':
                # Cifrar AES
                print("\n--- CIFRAGEM AES ---")
                plaintext_file = get_input("Arquivo de entrada (claro): ")
                if not plaintext_file:
                    continue
                
                key = get_input("Chave: ")
                if not key:
                    continue
                
                key_size = get_input("Tamanho da chave (128/192/256): ", [128, 192, 256], int)
                if not key_size:
                    continue
                
                mode = get_input("Modo de operação (ECB/CBC): ", ['ECB', 'CBC', 'ecb', 'cbc'])
                if not mode:
                    continue
                
                iv = None
                if mode.upper() == 'CBC':
                    iv = get_input("Vetor de Inicialização (IV): ")
                    if not iv:
                        continue
                
                key_format = get_input("Formato da chave/IV (HEX/UTF8): ", ['HEX', 'UTF8', 'hex', 'utf8'])
                if not key_format:
                    continue
                
                output_format = get_input("Formato de saída (HEX/BASE64): ", ['HEX', 'BASE64', 'hex', 'base64'])
                if not output_format:
                    continue
                
                output_file = get_input("Arquivo de saída: ")
                if not output_file:
                    continue
                
                crypto.aes_encrypt(plaintext_file, key, iv, key_size, mode, output_format, key_format, output_file)
            
            elif choice == '2':
                # Decifrar AES
                print("\n--- DECIFRAGEM AES ---")
                ciphertext_file = get_input("Arquivo de entrada (cifrado): ")
                if not ciphertext_file:
                    continue
                
                key = get_input("Chave: ")
                if not key:
                    continue
                
                key_size = get_input("Tamanho da chave (128/192/256): ", [128, 192, 256], int)
                if not key_size:
                    continue
                
                mode = get_input("Modo de operação (ECB/CBC): ", ['ECB', 'CBC', 'ecb', 'cbc'])
                if not mode:
                    continue
                
                iv = None
                if mode.upper() == 'CBC':
                    iv = get_input("Vetor de Inicialização (IV): ")
                    if not iv:
                        continue
                
                key_format = get_input("Formato da chave/IV (HEX/UTF8): ", ['HEX', 'UTF8', 'hex', 'utf8'])
                if not key_format:
                    continue
                
                input_format = get_input("Formato de entrada (HEX/BASE64): ", ['HEX', 'BASE64', 'hex', 'base64'])
                if not input_format:
                    continue
                
                output_file = get_input("Arquivo de saída: ")
                if not output_file:
                    continue
                
                crypto.aes_decrypt(ciphertext_file, key, iv, key_size, mode, input_format, key_format, output_file)
            
            elif choice == '3':
                # Gerar chaves RSA
                print("\n--- GERAÇÃO DE CHAVES RSA ---")
                key_size = get_input("Tamanho da chave (1024/2048): ", [1024, 2048], int)
                if not key_size:
                    continue
                
                private_key_file = get_input("Arquivo para chave privada: ")
                if not private_key_file:
                    continue
                
                public_key_file = get_input("Arquivo para chave pública: ")
                if not public_key_file:
                    continue
                
                crypto.generate_rsa_keys(key_size, private_key_file, public_key_file)
            
            elif choice == '4':
                # Assinar RSA
                print("\n--- ASSINATURA RSA ---")
                private_key_file = get_input("Arquivo com chave privada: ")
                if not private_key_file:
                    continue
                
                plaintext_file = get_input("Arquivo em claro: ")
                if not plaintext_file:
                    continue
                
                signature_file = get_input("Arquivo para assinatura: ")
                if not signature_file:
                    continue
                
                sha_version = get_input("Versão SHA-2 (256/384/512): ", [256, 384, 512], int)
                if not sha_version:
                    continue
                
                output_format = get_input("Formato de saída (HEX/BASE64): ", ['HEX', 'BASE64', 'hex', 'base64'])
                if not output_format:
                    continue
                
                crypto.rsa_sign(private_key_file, plaintext_file, signature_file, sha_version, output_format)
            
            elif choice == '5':
                # Verificar assinatura RSA
                print("\n--- VERIFICAÇÃO DE ASSINATURA RSA ---")
                public_key_file = get_input("Arquivo com chave pública: ")
                if not public_key_file:
                    continue
                
                plaintext_file = get_input("Arquivo em claro: ")
                if not plaintext_file:
                    continue
                
                signature_file = get_input("Arquivo com assinatura: ")
                if not signature_file:
                    continue
                
                sha_version = get_input("Versão SHA-2 (256/384/512): ", [256, 384, 512], int)
                if not sha_version:
                    continue
                
                input_format = get_input("Formato da assinatura (HEX/BASE64): ", ['HEX', 'BASE64', 'hex', 'base64'])
                if not input_format:
                    continue
                
                crypto.rsa_verify(public_key_file, plaintext_file, signature_file, sha_version, input_format)
            
            elif choice == '0':
                print("\nEncerrando programa...")
                break
            
            else:
                print("✗ Opção inválida")
        
        except KeyboardInterrupt:
            print("\n\n✗ Operação interrompida pelo usuário")
        except Exception as e:
            print(f"\n✗ Erro inesperado: {e}")


if __name__ == "__main__":
    print("\nBem-vindo ao Sistema de Criptografia!")
    print("Certifique-se de ter instalado: pip install cryptography")
    main()