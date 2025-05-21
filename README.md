HEAD
# SEE-U-L4TER-Uma-C-psula-do-Tempo-Criptogr-fica


# SEE-U-L4TER: Uma Cápsula do Tempo Criptográfica

## Descrição

Este projeto implementa um sistema de cifragem de ficheiros que só podem ser decifrados numa data e hora específicas. Baseia-se numa arquitetura cliente-servidor web, onde:

- O servidor (implementado em Flask) gere a autenticação, geração de chaves e operações de cifragem/decifragem.
- O cliente (interface CLI em Python) permite aos utilizadores interagir facilmente com o servidor.

As chaves são geradas dinamicamente a partir do email do utilizador, um segredo escolhido e a data/hora pretendida, garantindo que um ficheiro só pode ser decifrado na data e hora corretas.

---

## Funcionalidades

- Registo e login de utilizadores com hash seguro das passwords.
- Geração de chave AES baseada em email, segredo e data/hora.
- Cifragem de ficheiros com AES-128 (modos CBC ou CTR).
- Validação da integridade via HMAC (SHA256 ou SHA512).
- Armazenamento simples dos dados em ficheiro JSON (`Storage.json`).
- Pastas separadas para ficheiros cifrados (`cifrados/`) e decifrados (`decifrados/`).
- Interface CLI para operações fáceis e seguras.

---

## Requisitos

- Python 3.8+
- Instalar dependências com:

```bash
pip install -r Requirements.txt
```

---

## Como usar

### 1. Arrancar o servidor

Na pasta do projeto, executa:

```bash
python app.py
```

O servidor Flask ficará ativo e à espera de pedidos.

### 2. Executar o cliente CLI

Noutro terminal, na mesma pasta:

```bash
python interface_cli.py
```

O cliente tentará conectar ao servidor local e mostrar o menu interativo.

### 3. Operações no cliente CLI

#### Menu Principal (antes do login)

- Registar utilizador: criar nova conta.
- Login: autenticar utilizador.
- Ver chave da data/hora atual (pública).
- Sair: terminar o programa.

#### Menu Autenticado (após login)

1. Cifrar ficheiro  
   - Indicar segredo pessoal.  
   - Indicar data e hora para decifragem (`YYYY-MM-DD HH:MM`).  
   - Indicar caminho do ficheiro local a cifrar (ex: `cifrados/teste_de_cifra.txt`).  
   - Escolher modo de cifra (CBC ou CTR).  
   - Escolher algoritmo HMAC (SHA256 ou SHA512).  
   - Confirmar operação.  
   Receberá um ID da mensagem cifrada para usar depois.

2. Decifrar ficheiro  
   - Indicar segredo usado na cifragem.  
   - Indicar ID da mensagem cifrada.  
   - Confirmar operação.  
   O ficheiro decifrado ficará guardado na pasta `decifrados/` com nome baseado no ID.

3. Listar mensagens disponíveis: ver mensagens cifradas associadas ao utilizador.

4. Logout: terminar sessão.

### Nota sobre caminhos de ficheiros

- O caminho deve ser acessível localmente pelo cliente CLI.  
- Pode ser relativo à pasta atual ou absoluto.  
- Exemplo: `cifrados/teste_de_cifra.txt` ou caminho absoluto Linux `/home/usuario/projeto/cifrados/teste_de_cifra.txt`.  
- Se o ficheiro não existir, o cliente avisará para corrigir.

---

## Estrutura do Projeto

```
.
├── app.py                  # Servidor Flask
├── interface_cli.py        # Cliente CLI Python
├── CryptoUtils.py          # Funções de cifragem e HMAC
├── Storage.json            # Dados persistentes (utilizadores, mensagens)
├── cifrados/               # Ficheiros cifrados guardados
├── decifrados/             # Ficheiros decifrados guardados
├── json_tests/             # Exemplos de testes JSON
├── Requirements.txt        # Dependências Python
└── README.md               # Este ficheiro
```

---

## Segurança

- Passwords com hash SHA256 + salt.  
- Chaves baseadas em dados pessoais e temporais.  
- IV aleatório e HMAC para proteger cifragem.  
- Recomenda-se HTTPS em produção.

---
Implementação do sistema de cifragem com chave baseada em data/hora e interface cliente-servidor
