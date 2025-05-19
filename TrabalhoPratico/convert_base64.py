# Ferramenta adicional para ajudar a codificar ficheiros em base 64;
# Útil se estivesse a submeter os ficheiros em json, mas é melhor em upload direto
#
# Uso
# python3 convert_base64.py test.txt
# Retorna
#  ::: test.txt →→→ (Base64) :::
#  SGVsbG8gV29ybGQhCg==

import base64, argparse, sys
from pathlib import Path

#Ler o conteúdo do ficheiro em binário;
#Retorna em string base64.

def encode_file_base64(path: Path) -> str:
    data = path.read_bytes()
    return base64.b64encode(data).decode('utf-8')

def main():
    parser = argparse.ArgumentParser(
        description="Codificar ficheiro em base64"
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="Path do ficheiro a codificar"
    )
    args = parser.parse_args()

    for file_path in args.files:
        if not file_path.is_file():
            print(f"{file_path} não é um ficheiro válido")
            continue

        b64 = encode_file_base64(file_path)
        print(f"::: {file_path} →→→ (Base64) :::")
        print(b64, "\n")

if __name__ == "__main__":
    main()