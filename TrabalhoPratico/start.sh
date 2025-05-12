#!/bin/bash

# Procurar uma porta livre entre 5000 e 5050
for port in {5000..5050}; do
    if ! lsof -i :$port &> /dev/null; then
        echo "✅ A arrancar Flask na porta $port"
        export PORT=$port
        python3 app.py
        exit 0
    fi
done

echo "Não há portas livres entre 5000 e 5050."
exit 1
