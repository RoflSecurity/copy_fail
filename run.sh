#!/bin/bash
# run.sh - Exécute uniquement le binaire

echo "========================================"
echo "   CVE-2026-31431 - Copy Fail Exploit   "
echo "                 Exécution              "
echo "========================================"

if [ ! -f "./copy_fail" ]; then
    echo "[-] Erreur : ./copy_fail n'existe pas."
    echo "    Veuillez d'abord exécuter ./compile.sh"
    exit 1
fi

chmod +x ./copy_fail 2>/dev/null || true

echo "[+] Lancement de l'exploit..."
echo "========================================"

./copy_fail
