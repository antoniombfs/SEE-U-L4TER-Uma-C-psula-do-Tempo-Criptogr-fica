from flask import Flask, request, jsonify
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from CryptoUtils import gerar_chave, cifrar_dados, gerar_hmac, decifrar_dados
import json
import hmac
import os

app = Flask(__name__)

# Limite máximo de upload 5MB
app.config['MAX_CONTENT_SIZE'] = 5*1024*1024
# Localização ficheiro uploads
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.errorhandler(RequestEntityTooLarge)
def check_file_size(e):
    return jsonify({'erro': 'Ficheiro demasiado grande'}), 413

@app.route('/verificar_chave', methods=['GET'])
def verificar_chave():
    email = request.args.get('email')
    if not email:
        return jsonify({"erro": "Falta o parâmetro 'email'"}), 400

    data_hora = datetime.now().strftime("%Y%m%d%H%M")
    chave = gerar_chave(email, data_hora)
    return jsonify({"chave_hex": chave.hex(), "data_hora": data_hora})

@app.route('/time', methods=['GET'])
def server_time():
    data_hora = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return jsonify({"server_time": data_hora})

@app.route('/cifrar', methods=['POST'])
def cifrar():
    email = request.form.get('email')
    file = request.files.get('file')

    #Verificação
    if not email or file is None:
        return jsonify({"erro": "Falta 'email' ou 'file' no form"}), 400

    if file.filename == '':
        return jsonify({'erro': 'Ficheiro sem nome'}), 400

    #Gerar chave
    data_hora = datetime.now().strftime("%Y%m%d%H%M")
    chave = gerar_chave(email, data_hora)

    #Tratar file
    filename = secure_filename(file.filename) #werkzeug name clean
    out_name = f"{data_hora}_{filename}.enc"
    out_path = os.path.join(app.config['UPLOAD_FOLDER'], out_name)

    #Ler e cifrar bytes
    conteudo = file.read()
    criptograma = cifrar_dados(conteudo, chave)
    mac = gerar_hmac(chave, criptograma)

    with open(out_path, 'wb') as f_out:
        f_out.write(criptograma)


    # Atualiza o Storage.json
    with open('Storage.json', 'r+') as f:
        try: storage = json.load(f)
        except json.JSONDecodeError: storage = {"registos":[]} # remover se não querem assim
        storage['registos'].append({
            'email': email,
            'data_hora': data_hora,
            'file_path': out_path,
            'hmac': mac.hex()
        })
        f.seek(0)
        json.dump(storage, f, indent=2)
        f.truncate()

    return jsonify({
        "file_path": out_path,
        "hmac": mac.hex(),
        "data_hora": data_hora
    }), 200

@app.route('/decifrar', methods=['POST'])
def decifrar():
    data = request.json or {}
    email = data.get('email')
    data_hora = data.get('data_hora')
    file_path = data.get('file_path')
    hmac_hex = data.get('hmac')

    if not all([email, data_hora, file_path, hmac_hex]):
        return jsonify({"erro": "Faltam parâmetros no body"}), 400
    
    if not os.path.isfile(file_path):
        return jsonify({"erro": "Ficheiro não encontrado"}), 404
    #Ler ficheiro
    try:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
    except Exception as e: return jsonify({"erro": "Erro ao ler o ficheiro"}), 500

    chave = gerar_chave(email, data_hora)

    # Verificar HMAC
    try:
        hmac_bytes = bytes.fromhex(hmac_hex)
        mac_calculado = gerar_hmac(chave, file_bytes)
    except Exception as e: return jsonify({"erro": "HMAC inválido ou formato errado"}), 400        

    if not hmac.compare_digest(mac_calculado, hmac_bytes):
        return jsonify({"erro": "HMAC inválido - integridade comprometida"}), 400

    # Decifrar mensagem
    plain_bytes = decifrar_dados(file_bytes, chave)
    try:
        mensagem = plain_bytes.decode('utf-8', errors='ignore')
    except UnicodeDecodeError: #edge case
        import base64
        mensagem = base64.b64decode(plain_bytes).decode('utf-8')

    return jsonify({"mensagem_decifrada": mensagem}), 200

if __name__ == '__main__':
    import os

port = int(os.environ.get("PORT", 5000))
app.run(debug=True, port=port)
