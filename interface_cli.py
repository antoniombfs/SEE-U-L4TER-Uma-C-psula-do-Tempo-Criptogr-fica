import requests
import os
import sys
from colorama import init, Fore
import base64
import getpass
from datetime import datetime, timedelta
import re

init(autoreset=True)

#Limite máximo de 1GB de ficheiros
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def testar_porta(porta):
    try:
        url = f"http://127.0.0.1:{porta}/"
        resp = requests.get(url, timeout=1)
        if resp.status_code == 200:
            return True
    except requests.exceptions.RequestException:
        return False
    return False

def encontrar_base_url():
    for porta in range(5000, 5051):
        if testar_porta(porta):
            return f"http://127.0.0.1:{porta}"
    print(Fore.RED + "Servidor Flask não encontrado em portas 5000-5050.")
    sys.exit(1)

BASE_URL = encontrar_base_url()
print(Fore.GREEN + f"Conectado a {BASE_URL}")

token = None
email_logado = None

def input_confirmar(mensagem="Tem a certeza? (s/n): "):
    while True:
        resposta = input(mensagem).strip().lower()
        if resposta in ['s', 'sim']:
            return True
        elif resposta in ['n', 'não', 'nao']:
            return False
        else:
            print(Fore.YELLOW + "Resposta inválida. Por favor responda com 's' ou 'n'.")

def menu_principal():
    clear_console()
    print(Fore.CYAN + "=== SEE-U-L4TER - CLIENTE CLI ===")
    print("1. Registar utilizador")
    print("2. Login")
    print("3. Sair")

def menu_autenticado():
    clear_console()
    print(Fore.CYAN + f"=== Menu Utilizador: {email_logado} ===")
    print("1. Cifrar ficheiro")
    print("2. Decifrar ficheiro")
    print("3. Listar mensagens disponíveis")
    print("4. Ver chave pública da data/hora atual (sem segredo)")
    print("5. Logout")

def email_valido(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def registar():
    print(Fore.YELLOW + "== Registar Utilizador ==")
    email = input("Email: ").strip()
    if not email_valido(email):
        print(Fore.RED + "Email inválido")
        input("Pressione Enter para continuar...")
        return
    #password = input("Password: ").strip() pode ser lido no terminal (echoing)
    password = getpass.getpass("Password: ").strip()
    confirm_password = getpass.getpass("Confirmar Password: ").strip()
    if password != confirm_password:
        print("Password não coincide.")
        input("Pressione Enter para voltar...")
        return
    resp = requests.post(f"{BASE_URL}/registar", json={"email": email, "password": password})
    data = resp.json()
    if resp.status_code == 201:
        print(Fore.GREEN + data.get("sucesso", "Registo com sucesso!"))
    else:
        print(Fore.RED + data.get("erro", "Erro no registo."))
        input("Pressione Enter para continuar...")

def login():
    global token, email_logado
    print(Fore.YELLOW + "== Login ==")
    email = input("Email: ").strip()
    if not email_valido(email):
        print(Fore.RED + "Email inválido")
        input("Pressione Enter para continuar...")
        return
    #password = input("Password: ").strip()
    password = getpass.getpass("Password: ").strip()
    resp = requests.post(f"{BASE_URL}/login", json={"email": email, "password": password})
    data = resp.json()
    if resp.status_code == 200:
        token = data.get("token")
        email_logado = email
        print(Fore.GREEN + "Login bem-sucedido!")
    else:
        print(Fore.RED + data.get("erro", "Erro no login."))
    input("Pressione Enter para continuar...")

def logout():
    global token, email_logado
    if input_confirmar("Quer mesmo fazer logout? (s/n): "):
        token = None
        email_logado = None
        print(Fore.GREEN + "Logout efetuado.")
    else:
        print("Logout cancelado.")
    input("Pressione Enter para continuar...")

def ler_ficheiro_bytes(caminho):
    try:
        with open(caminho, 'rb') as f:
            if os.path.getsize(caminho) > MAX_FILE_SIZE:
                print(Fore.RED + "Ficheiro demasiado grande")
                return None
            return f.read()
    except Exception as e:
        print(Fore.RED + f"Erro a ler ficheiro: {e}")
        return None

def escolher_opcao_lista(mensagem, opcoes):
    print(mensagem)
    for i, opcao in enumerate(opcoes, 1):
        print(f"{i}. {opcao}")
    while True:
        escolha = input("Escolha uma opção: ").strip()
        if escolha.isdigit() and 1 <= int(escolha) <= len(opcoes):
            return opcoes[int(escolha) - 1]
        else:
            print(Fore.YELLOW + "Opção inválida, tente novamente.")

def ler_data_hora(input):
    #Retorna a hora resultante depois de verificar o input
    #Também retorna um bool caso o input seja data relativa
    input = input.strip().lower()
    data_atual = datetime.now()

    #Data relativa - y:ano m:mes d:dia h:hora min:minuto
    pattern = re.match(r"(\d+)(y|m|d|h|min)$", input)
    if pattern:
        amount = int(pattern.group(1))
        unit = pattern.group(2)

        if unit == 'y':
            try:
                return data_atual.replace(year=data_atual.year+amount), True
            except ValueError:
                #Dias inválidos em certos meses
                return data_atual.replace(year=data_atual+amount, day=28), True
        elif unit == 'm':
            mes_total = data_atual.month + amount
            ano = data_atual.year + (mes_total-1)//12
            mes = (mes_total-1)%12+1
            dia = min(data_atual.day,28)#Evita dias inválidos
            try:
                return data_atual.replace(year=ano, month=mes, day=dia), True
            except ValueError:
                return data_atual.replace(year=ano, month=mes, day=28), True
        elif unit == 'd':
            return data_atual + timedelta(days=amount), True
        elif unit == 'h':
            return data_atual + timedelta(hours=amount), True
        elif unit == 'min':
            return data_atual + timedelta(minutes=amount), True
    #Formato completo
    try:
        return datetime.strptime(input, "%Y-%m-%d %H:%M"), False
    except ValueError:
        print(Fore.RED + "Formato inválido")
        return None, False

def cifrar():
    if not token:
        print(Fore.RED + "Tem de fazer login primeiro.")
        input("Pressione Enter para continuar...")
        return
    print(Fore.YELLOW + "== Cifrar Ficheiro ==")
    segredo = input("Segredo: ").strip()
    data_hora, data_relativa = ler_data_hora(input("Data e hora (YYYY-MM-DD HH:MM)[Xy,Xm,Xd,Xh,Xmin]:\n"))
    if not data_hora:
        input("Pressione Enter para continuar...")
        return
    data_hora = data_hora.strftime("%Y-%m-%d %H:%M")
    if data_relativa:
        print("Data: " + data_hora)
    caminho_ficheiro = input("Caminho do ficheiro a cifrar: ").strip()

    dados_bytes = ler_ficheiro_bytes(caminho_ficheiro)
    if dados_bytes is None:
        input("Pressione Enter para continuar...")
        return

    modo_cifra = escolher_opcao_lista("Escolha o modo de cifra:", ["CBC", "CTR"])
    algoritmo_hmac = escolher_opcao_lista("Escolha o algoritmo HMAC:", ["SHA256", "SHA512"])

    if not input_confirmar("Confirma a cifragem? (s/n): "):
        print("Cifragem cancelada.")
        input("Pressione Enter para continuar...")
        return

    payload = {
        "email": email_logado,
        "segredo": segredo,
        "data_hora": data_hora,
        "mensagem": base64.b64encode(dados_bytes).decode(),
        "modo_cifra": modo_cifra,
        "algoritmo_hmac": algoritmo_hmac
    }
    headers = {"Authorization": token}
    resp = requests.post(f"{BASE_URL}/cifrar", json=payload, headers=headers)
    try:
        data = resp.json()
        if resp.status_code == 200:
            print(Fore.GREEN + f"Sucesso! ID da mensagem: {data.get('id')}")
        else:
            print(Fore.RED + data.get("erro", "Erro ao cifrar ficheiro."))
    except Exception:
        print(Fore.RED + "Resposta inválida do servidor.")
    input("Pressione Enter para continuar...")

def decifrar():
    if not token:
        print(Fore.RED + "Tem de fazer login primeiro.")
        input("Pressione Enter para continuar...")
        return
    print(Fore.YELLOW + "== Decifrar Ficheiro ==")
    segredo = input("Segredo: ").strip()
    msg_id = input("ID da mensagem a decifrar: ").strip()
    if not input_confirmar("Confirma a decifragem? (s/n): "):
        print("Decifragem cancelada.")
        input("Pressione Enter para continuar...")
        return

    payload = {
        "email": email_logado,
        "segredo": segredo,
        "id": msg_id
    }
    headers = {"Authorization": token}
    resp = requests.post(f"{BASE_URL}/decifrar", json=payload, headers=headers)

    try:
        data = resp.json()
        if resp.status_code == 200:
            texto_base64 = data.get('texto')
            if texto_base64:
                dados_decifrados = base64.b64decode(texto_base64)

                caminho_saida_default = f"decifrados/{msg_id}_decifrado.bin"
                print(f"Ficheiro decifrado será guardado em: {caminho_saida_default}")
                usar_default = input("Usar este caminho? (s/n): ").strip().lower()
                if usar_default in ['s', 'sim', '']:
                    caminho_saida = caminho_saida_default
                else:
                    caminho_saida = input("Indique o caminho para guardar o ficheiro decifrado: ").strip()

                os.makedirs(os.path.dirname(caminho_saida), exist_ok=True)

                with open(caminho_saida, 'wb') as f:
                    f.write(dados_decifrados)
                print(Fore.GREEN + f"Ficheiro guardado em: {caminho_saida}")

                extensao = input("Qual é a extensão original do ficheiro? (ex: .png, .jpg, .webp, .txt) ").strip()
                if extensao and not extensao.startswith('.'):
                    extensao = '.' + extensao
                novo_caminho = os.path.splitext(caminho_saida)[0] + extensao
                os.rename(caminho_saida, novo_caminho)
                print(Fore.GREEN + f"Ficheiro renomeado para: {novo_caminho}")

            else:
                print(Fore.RED + "Resposta do servidor não contém dados decifrados.")
        else:
            erro = data.get("erro", "Erro ao decifrar ficheiro.")
            print(Fore.RED + f"Erro: {erro}")
    except Exception as e:
        print(Fore.RED + f"Resposta inválida do servidor: {e}")
    input("Pressione Enter para continuar...")

def chave_publica_atual():
    if not email_logado:
        print(Fore.RED + "Tem de fazer login primeiro.")
        input("Pressione Enter para continuar...")
        return
    headers = {"Authorization": token}
    params = {"email": email_logado}
    resp = requests.get(f"{BASE_URL}/chave_publica_atual", params=params, headers=headers)
    try:
        data = resp.json()
        if resp.status_code == 200:
            print(Fore.GREEN + f"→Chave pública para {data.get('data_hora')}:\n {data.get('chave_hex')}")
        else:
            print(Fore.RED + data.get("erro", "Erro ao obter chave pública."))
    except Exception:
        print(Fore.RED + "Resposta inválida do servidor.")
    input("Pressione Enter para continuar...")

def listar_mensagens():
    if not token:
        print(Fore.RED + "Tem de fazer login primeiro.")
        input("Pressione Enter para continuar...")
        return
    print(Fore.YELLOW + "== Listar Mensagens ==")
    headers = {"Authorization": token}
    params = {"email": email_logado}
    resp = requests.get(f"{BASE_URL}/mensagens", headers=headers, params=params)
    try:
        data = resp.json()
        if resp.status_code == 200:
            mensagens = data.get("mensagens", [])
            if mensagens:
                print("\nMensagens disponíveis:")
                for msg in mensagens:
                    print(f"ID: {msg['id']} | Data/Hora: {msg['data_hora']}")
            else:
                print("Nenhuma mensagem encontrada para este utilizador.")
        else:
            print(Fore.RED + data.get("erro", "Erro ao listar mensagens."))
    except Exception:
        print(Fore.RED + "Resposta inválida do servidor.")
    input("Pressione Enter para continuar...")

def main():
    global token, email_logado
    while True:
        if not token:
            menu_principal()
            escolha = input("Escolha uma opção: ").strip()
            if escolha == '1':
                registar()
            elif escolha == '2':
                login()
            elif escolha == '3':
                print("A sair...")
                break
            else:
                print(Fore.RED + "Opção inválida, tente novamente.")
        else:
            menu_autenticado()
            escolha = input("Escolha uma opção: ").strip()
            if escolha == '1':
                cifrar()
            elif escolha == '2':
                decifrar()
            elif escolha == '3':
                listar_mensagens()
            elif escolha == '4':
                chave_publica_atual()
            elif escolha == '5':
                logout()
            else:
                print(Fore.RED + "Opção inválida, tente novamente.")

if __name__ == "__main__":
    main()
