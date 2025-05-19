from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import hmac

SEGREDO_SISTEMA = "SegredoUltraConfidencial"

def gerar_chave(email, data_hora):
    base = f"{email}|{SEGREDO_SISTEMA}|{data_hora}"
    chave = hashlib.sha256(base.encode()).digest()[:16]  # AES-128 (16 bytes)
    return chave

def cifrar_dados(plain_text: bytes, chave: bytes) -> bytes:
    block_size = 16
    iv = get_random_bytes(block_size)
    cipher = AES.new(chave, AES.MODE_CBC, iv)

    padding_length = block_size - (len(plain_text) % block_size)
    padding = bytes([padding_length] * padding_length)
    padded_text = plain_text + padding
    
    cipher_text = cipher.encrypt(padded_text)
    return iv + cipher_text  # IV + CipherText

def gerar_hmac(chave, mensagem_bytes):
    mac = hmac.new(chave, mensagem_bytes, hashlib.sha256).digest()
    return mac

def decifrar_dados(criptograma_bytes, chave):
    iv = criptograma_bytes[:16]
    cipher_text = criptograma_bytes[16:]
    cipher = AES.new(chave, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(cipher_text)
    padding_length = padded_data[-1]
    plain_text = padded_data[:-padding_length]
    return plain_text
