import socket
from flask import Flask, request, jsonify
from datetime import datetime
import hashlib
import hmac
import json
import os
import uuid
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

STORAGE_FILE = "Storage.json"

# ---------------------------
# Utilitários para Storage JSON
# ---------------------------
def load_storage():
    if not os.path.exists(STORAGE_FILE):
        return {"users": {}, "registos": []}
    with open(STORAGE_FILE, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = {}
    if "users" not in data:
        data["users"] = {}
    if "registos" not in data:
        data["registos"] = []
    return data

def save_storage(data):
    with open(STORAGE_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ---------------------------
# Segurança
# ---------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = uuid.uuid4().hex
    hash_pw = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, hash_pw

def verify_password(password, salt, hash_pw):
    return hashlib.sha256((salt + password).encode()).hexdigest() == hash_pw

def gerar_chave(email, segredo, data_hora):
    base = f"{email}|{segredo}|{data_hora}"
    chave = hashlib.sha256(base.encode()).digest()[:16]
    return chave

def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def cifrar_dados(plain_bytes, chave, modo='CBC'):
    if modo == 'CBC':
        iv = get_random_bytes(16)
        cipher = AES.new(chave, AES.MODE_CBC, iv)
        padded = pkcs7_pad(plain_bytes)
        cipher_text = cipher.encrypt(padded)
        return iv + cipher_text
    elif modo == 'CTR':
        cipher = AES.new(chave, AES.MODE_CTR)
        cipher_text = cipher.encrypt(plain_bytes)
        return cipher.nonce + cipher_text
    else:
        raise ValueError("Modo não suportado")

def decifrar_dados(criptograma_bytes, chave, modo='CBC'):
    if modo == 'CBC':
        iv = criptograma_bytes[:16]
        cipher_text = criptograma_bytes[16:]
        cipher = AES.new(chave, AES.MODE_CBC, iv)
        padded = cipher.decrypt(cipher_text)
        return pkcs7_unpad(padded)
    elif modo == 'CTR':
        nonce = criptograma_bytes[:8]
        cipher_text = criptograma_bytes[8:]
        cipher = AES.new(chave, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(cipher_text)
    else:
        raise ValueError("Modo não suportado")

def gerar_hmac(chave, mensagem_bytes, algoritmo='SHA256'):
    if algoritmo == 'SHA256':
        return hmac.new(chave, mensagem_bytes, hashlib.sha256).hexdigest()
    elif algoritmo == 'SHA512':
        return hmac.new(chave, mensagem_bytes, hashlib.sha512).hexdigest()
    else:
        raise ValueError("Algoritmo HMAC não suportado")

def verificar_hmac(chave, mensagem_bytes, mac_hex, algoritmo='SHA256'):
    if algoritmo == 'SHA256':
        mac_calculado = hmac.new(chave, mensagem_bytes, hashlib.sha256).hexdigest()
    elif algoritmo == 'SHA512':
        mac_calculado = hmac.new(chave, mensagem_bytes, hashlib.sha512).hexdigest()
    else:
        return False
    return hmac.compare_digest(mac_calculado, mac_hex)

# ---------------------------
# Endpoints
# ---------------------------

@app.route("/registar", methods=["POST"])
def registar():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"erro": "Email e password são obrigatórios"}), 400

    storage = load_storage()
    if email in storage["users"]:
        return jsonify({"erro": "Utilizador já existe"}), 400

    salt, hash_pw = hash_password(password)
    storage["users"][email] = {"salt": salt, "hash": hash_pw}
    save_storage(storage)
    return jsonify({"sucesso": "Utilizador registado com sucesso"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"erro": "Email e password são obrigatórios"}), 400

    storage = load_storage()
    user = storage["users"].get(email)
    if not user or not verify_password(password, user["salt"], user["hash"]):
        return jsonify({"erro": "Credenciais inválidas"}), 401

    token = uuid.uuid4().hex
    user["token"] = token
    save_storage(storage)

    return jsonify({"sucesso": "Login efetuado", "token": token})

@app.route("/cifrar", methods=["POST"])
def cifrar():
    data = request.json
    token = request.headers.get("Authorization")
    email = data.get("email")
    segredo = data.get("segredo")
    data_hora = data.get("data_hora")
    mensagem_base64 = data.get("mensagem")
    modo_cifra = data.get("modo_cifra", "CBC")
    algoritmo_hmac = data.get("algoritmo_hmac", "SHA256")

    if not all([token, email, segredo, data_hora, mensagem_base64]):
        return jsonify({"erro": "Faltam parâmetros ou token"}), 400

    storage = load_storage()
    user = storage["users"].get(email)
    if not user or user.get("token") != token:
        return jsonify({"erro": "Token inválido ou utilizador não autenticado"}), 401

    try:
        mensagem_bytes = base64.b64decode(mensagem_base64)
    except Exception:
        return jsonify({"erro": "Mensagem base64 inválida"}), 400

    chave = gerar_chave(email, segredo, data_hora)
    try:
        criptograma = cifrar_dados(mensagem_bytes, chave, modo=modo_cifra)
    except Exception as e:
        return jsonify({"erro": f"Erro na cifragem: {str(e)}"}), 500

    try:
        mac_hex = gerar_hmac(chave, criptograma, algoritmo=algoritmo_hmac)
    except Exception as e:
        return jsonify({"erro": f"Erro no cálculo do HMAC: {str(e)}"}), 500

    criptograma_hex = criptograma.hex()
    msg_id = uuid.uuid4().hex
    registo = {
        "id": msg_id,
        "email": email,
        "data_hora": data_hora,
        "criptograma": criptograma_hex,
        "hmac": mac_hex,
        "modo_cifra": modo_cifra,
        "algoritmo_hmac": algoritmo_hmac
    }
    storage["registos"].append(registo)
    save_storage(storage)

    return jsonify({"sucesso": "Mensagem cifrada e armazenada", "id": msg_id})

@app.route("/decifrar", methods=["POST"])
def decifrar():
    data = request.json
    token = request.headers.get("Authorization")
    email = data.get("email")
    segredo = data.get("segredo")
    msg_id = data.get("id")

    if not all([token, email, segredo, msg_id]):
        return jsonify({"erro": "Faltam parâmetros ou token"}), 400

    storage = load_storage()
    user = storage["users"].get(email)
    if not user or user.get("token") != token:
        return jsonify({"erro": "Token inválido ou utilizador não autenticado"}), 401

    mensagem = next((m for m in storage["registos"] if m["id"] == msg_id), None)
    if not mensagem:
        return jsonify({"erro": "Mensagem não encontrada"}), 404

    if mensagem["email"] != email:
        return jsonify({"erro": "Sem permissão para aceder a esta mensagem"}), 403

    chave = gerar_chave(email, segredo, mensagem["data_hora"])
    criptograma = bytes.fromhex(mensagem["criptograma"])
    mac_hex = mensagem["hmac"]
    modo_cifra = mensagem.get("modo_cifra", "CBC")
    algoritmo_hmac = mensagem.get("algoritmo_hmac", "SHA256")

    if not verificar_hmac(chave, criptograma, mac_hex, algoritmo=algoritmo_hmac):
        return jsonify({"erro": "Falha na verificação de integridade (HMAC)"}), 403

    data_hora_msg = datetime.strptime(mensagem["data_hora"], "%Y-%m-%d %H:%M")
    agora = datetime.now()
    if agora < data_hora_msg:
        return jsonify({"erro": "Mensagem só pode ser decifrada após a data/hora correta"}), 403

    try:
        plain_bytes = decifrar_dados(criptograma, chave, modo=modo_cifra)
        texto_base64 = base64.b64encode(plain_bytes).decode()
    except Exception:
        return jsonify({"erro": "Erro ao decifrar a mensagem"}), 500

    return jsonify({"sucesso": "Mensagem decifrada", "texto": texto_base64})

@app.route("/chave_atual", methods=["GET"])
def chave_atual():
    email = request.args.get("email")
    segredo = request.args.get("segredo")
    if not email or not segredo:
        return jsonify({"erro": "Email e segredo são obrigatórios"}), 400

    agora = datetime.now().strftime("%Y-%m-%d %H:%M")
    chave = gerar_chave(email, segredo, agora)
    return jsonify({"data_hora": agora, "chave_hex": chave.hex()})

@app.route("/mensagens", methods=["GET"])
def listar_mensagens():
    token = request.headers.get("Authorization")
    email = request.args.get("email")

    if not token or not email:
        return jsonify({"erro": "Token e email são obrigatórios"}), 400

    storage = load_storage()
    user = storage["users"].get(email)
    if not user or user.get("token") != token:
        return jsonify({"erro": "Token inválido ou utilizador não autenticado"}), 401

    mensagens_user = [
        {"id": m["id"], "data_hora": m["data_hora"]}
        for m in storage["registos"] if m["email"] == email
    ]

    return jsonify({"mensagens": mensagens_user})

@app.route("/")
def index():
    return "Servidor SEE-U-L4TER em funcionamento!"

def find_free_port(start=5000, end=5050):
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    raise RuntimeError("Não foi possível encontrar porta livre")

if __name__ == "__main__":
    port = find_free_port()
    print(f"Servidor a iniciar na porta {port}...")
    app.run(debug=True, port=port)
