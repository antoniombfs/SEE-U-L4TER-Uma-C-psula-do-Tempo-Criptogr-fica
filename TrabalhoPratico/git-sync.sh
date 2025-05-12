#!/bin/bash

# Guardar alterações locais (se existirem)
echo "🔄 A verificar alterações locais..."
git status

# Adicionar ficheiros modificados automaticamente
git add .

# Commit provisório (evita perder alterações)
git commit -m "Sync: guardar alterações locais antes de pull" || echo "ℹ️ Nada novo para commitar."

# Puxar as alterações do GitHub com rebase
echo "⬇️ A fazer pull --rebase do remote..."
git pull origin main --rebase

# Push final das tuas alterações
echo "⬆️ A enviar alterações para o GitHub..."
git push origin main

echo "✅ Sync concluído."
