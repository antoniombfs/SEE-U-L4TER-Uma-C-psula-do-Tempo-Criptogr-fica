from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Util.Padding import pad, unpad

def cifrar_dados(dados_bytes, chave_bytes, modo='CBC'):
    """
    Cifra dados (bytes) usando AES-128 no modo CBC ou CTR.
    - dados_bytes: bytes para cifrar
    - chave_bytes: chave de 16 bytes
    - modo: 'CBC' ou 'CTR'
    Retorna bytes cifrados com IV prefixado (IV + ciphertext).
    """
    iv = b'\x00' * 16  # Para simplificar, IV fixo; ideal gerar aleatório e prefixar
    if modo == 'CBC':
        cipher = AES.new(chave_bytes, AES.MODE_CBC, iv)
        dados_padded = pad(dados_bytes, AES.block_size)
        cifrado = cipher.encrypt(dados_padded)
    elif modo == 'CTR':
        cipher = AES.new(chave_bytes, AES.MODE_CTR)
        cifrado = cipher.encrypt(dados_bytes)
        iv = cipher.nonce  # CTR usa nonce
        cifrado = iv + cifrado  # prefixar nonce
    else:
        raise ValueError("Modo não suportado")
    if modo == 'CBC':
        return iv + cifrado
    else:
        return cifrado

def decifrar_dados(criptograma_bytes, chave_bytes, modo='CBC'):
    """
    Decifra dados cifrados.
    - criptograma_bytes: bytes com IV + ciphertext (modo CBC) ou nonce + ciphertext (CTR)
    - chave_bytes: chave de 16 bytes
    - modo: 'CBC' ou 'CTR'
    Retorna dados originais (bytes).
    """
    if modo == 'CBC':
        iv = criptograma_bytes[:16]
        cifrado = criptograma_bytes[16:]
        cipher = AES.new(chave_bytes, AES.MODE_CBC, iv)
        dados_padded = cipher.decrypt(cifrado)
        dados = unpad(dados_padded, AES.block_size)
    elif modo == 'CTR':
        nonce = criptograma_bytes[:8]
        cifrado = criptograma_bytes[8:]
        cipher = AES.new(chave_bytes, AES.MODE_CTR, nonce=nonce)
        dados = cipher.decrypt(cifrado)
    else:
        raise ValueError("Modo não suportado")
    return dados

def calcular_hmac(chave_bytes, dados_bytes, algoritmo='SHA256'):
    """
    Calcula HMAC (hex) usando chave e dados.
    - algoritmo: 'SHA256' ou 'SHA512'
    """
    if algoritmo == 'SHA256':
        h = HMAC.new(chave_bytes, digestmod=SHA256)
    elif algoritmo == 'SHA512':
        h = HMAC.new(chave_bytes, digestmod=SHA512)
    else:
        raise ValueError("Algoritmo HMAC não suportado")
    h.update(dados_bytes)
    return h.hexdigest()

def verificar_hmac(chave_bytes, dados_bytes, hmac_hex, algoritmo='SHA256'):
    """
    Verifica HMAC. Retorna True se válido, False se não.
    """
    try:
        if algoritmo == 'SHA256':
            h = HMAC.new(chave_bytes, digestmod=SHA256)
        elif algoritmo == 'SHA512':
            h = HMAC.new(chave_bytes, digestmod=SHA512)
        else:
            return False
        h.update(dados_bytes)
        h.verify(bytes.fromhex(hmac_hex))
        return True
    except ValueError:
        return False

def gerar_chave(email, segredo, data_hora):
    """
    Exemplo simples para gerar chave 16 bytes a partir de dados (substituir por função segura).
    """
    import hashlib
    base = f"{email}{segredo}{data_hora}".encode()
    return hashlib.sha256(base).digest()[:16]
