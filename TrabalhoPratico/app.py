from flask import Flask, request, jsonify
from datetime import datetime
from CryptoUtils import gerar_chave, cifrar_dados, gerar_hmac, decifrar_dados
import json
import hmac
import os

app = Flask(__name__)

@app.route('/verificar_chave', methods=['GET'])
def verificar_chave():
    email = request.args.get('email')
    if not email:
        return jsonify({"erro": "Falta o parâmetro 'email'"}), 400

    data_hora = datetime.now().strftime("%Y%m%d%H%M")
    chave = gerar_chave(email, data_hora)
    return jsonify({"chave_hex": chave.hex(), "data_hora": data_hora})

@app.route('/cifrar', methods=['POST'])
def cifrar():
    data = request.json
    email = data.get('email')
    mensagem = data.get('mensagem')

    if not email or not mensagem:
        return jsonify({"erro": "Falta 'email' ou 'mensagem' no body"}), 400

    data_hora = datetime.now().strftime("%Y%m%d%H%M")
    chave = gerar_chave(email, data_hora)
    criptograma = cifrar_dados(mensagem, chave)
    mac = gerar_hmac(chave, criptograma)

    # Guardar no Storage.json
    with open('Storage.json', 'r+') as f:
        storage = json.load(f)
        storage['registos'].append({
            'email': email,
            'data_hora': data_hora,
            'criptograma': criptograma.hex(),
            'hmac': mac.hex()
        })
        f.seek(0)
        json.dump(storage, f, indent=2)

    return jsonify({
        "criptograma": criptograma.hex(),
        "hmac": mac.hex(),
        "data_hora": data_hora
    })

@app.route('/decifrar', methods=['POST'])
def decifrar():
    data = request.json
    email = data.get('email')
    data_hora = data.get('data_hora')
    criptograma_hex = data.get('criptograma')
    hmac_hex = data.get('hmac')

    if not all([email, data_hora, criptograma_hex, hmac_hex]):
        return jsonify({"erro": "Faltam parâmetros no body"}), 400

    chave = gerar_chave(email, data_hora)
    criptograma_bytes = bytes.fromhex(criptograma_hex)
    hmac_bytes = bytes.fromhex(hmac_hex)

    # Verificar HMAC
    mac_calculado = gerar_hmac(chave, criptograma_bytes)
    if not hmac.compare_digest(mac_calculado, hmac_bytes):
        return jsonify({"erro": "HMAC inválido - integridade comprometida"}), 400

    # Decifrar mensagem
    plain_text = decifrar_dados(criptograma_bytes, chave)

    return jsonify({"mensagem_decifrada": plain_text})

if __name__ == '__main__':
    import os

port = int(os.environ.get("PORT", 5000))
app.run(debug=True, port=port)
