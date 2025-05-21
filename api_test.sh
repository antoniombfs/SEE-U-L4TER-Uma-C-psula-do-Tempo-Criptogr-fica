#!/bin/bash

# api_test.sh - Script para testar o API SEE-U-L4TER
# Uso:
#   ./api_test.sh -r <rota> [-j <ficheiro_json>] [-u <url_base>] [-q <query_string>]

set -euo pipefail

#Grupo das rotas e métodos do API
declare -A ROUTES=(
  [verificar_chave]=GET
  [time]=GET
  [cifrar]=POST
  [decifrar]=POST
)

#Defaults
URL_BASE="http://127.0.0.1:5000"
ROUTE=""
JSON_FILE=""
QUERY_STRING=""

GREEN_B="\033[1;32m"
LOW_C="\x1B[37m"
RST="\033[0m"
print_help() {
    cat <<EOF
    Uso: $0 [-l] [-r ROTA] [-j FICHEIRO_JSON] [-u URL_BASE] [-q QUERY_STRING]
        -l                  Lista todas as rotas suportadas
        -r ROTA             Rota da API: ${!ROUTES[*]}
        -j FICHEIRO_JSON    Ficheiro JSON com os dados para requisições POST
        -u URL_BASE         URL base da API (padrão: $URL_BASE)
        -q QUERY_STRING     String de query para requisições GET (ex: "email=teste@example.com")
        -h                  Mostrar esta ajuda
    Exemplos:
        ./api_test.sh -r time
        ./api_test.sh -r decifrar -j query.json
        ./api_test.sh -u 127.1:5000 -r decifrar -j json_tests/decifrar.json
EOF
}

#Param Parse
LIST_ONLY=0 #Apenas visualizar os endpoints

while getopts "lr:j:u:q:h" opt; do
    case "$opt" in
    l) LIST_ONLY=1 ;;
    r) ROUTE="$OPTARG" ;;
    j) JSON_FILE="$OPTARG" ;;
    u) URL_BASE="$OPTARG" ;;
    q) QUERY_STRING="$OPTARG" ;;
    h) print_help; exit 0 ;;
    *) print_help; exit 1 ;;
  esac
done

if (( LIST_ONLY )); then
    echo "Rotas suportadas:"
    for r in "${!ROUTES[@]}"; do
        printf "  - %-15s %s\n" "$r" "${ROUTES[$r]}"
    done
    exit 0
fi

#Verificação
if [[ -z "$ROUTE" ]]; then
    echo "A opção -r ROUTE é obrigatória" >&2
    print_help
    exit 1
fi

if [[ -z "${ROUTES[$ROUTE]+_}" ]]; then
  echo "Rota inválida: '$ROUTE' (definir no código, se necessário)" >&2
  print_help
  exit 1
fi

METHOD="${ROUTES[$ROUTE]}"

#Construir URL
URL="${URL_BASE}/${ROUTE}"
if [[ "$METHOD" == "GET" && -n "$QUERY_STRING" ]]; then
  URL="${URL}?${QUERY_STRING}"
fi

# Execução da requisição
echo -e "→→→${GREEN_B}${METHOD}${RST} @ ${LOW_C}${URL}${RST}"
if [[ "$METHOD" == "POST" ]]; then
  if [[ -z "$JSON_FILE" ]]; then
    echo "A opção -j é obrigatória para requisições POST." >&2
    exit 1
  fi
  if [[ ! -f "$JSON_FILE" ]]; then
    echo "Ficheiro JSON não encontrado: $JSON_FILE" >&2
    exit 1
  fi
  echo "←←←Content:"
  curl -s -X POST -H "Content-Type: application/json" --data @"$JSON_FILE" "$URL" | jq .
else
  curl -s -X GET "$URL" | jq .
fi

