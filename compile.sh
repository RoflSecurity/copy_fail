#!/bin/bash
# compile.sh - Compile uniquement

echo "========================================"
echo "   CVE-2026-31431 - Copy Fail Exploit   "
echo "               Compilation seule        "
echo "========================================"

if [ ! -f "copy_fail.c" ]; then
    echo "[-] Erreur : copy_fail.c non trouvé !"
    exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
    echo "[-] gcc n'est pas installé."
    exit 1
fi

echo "[+] Compilation en cours (version statique)..."

gcc -O2 -static -o copy_fail copy_fail.c -lz -lpthread

if [ $? -eq 0 ]; then
    echo "[+] Compilation réussie !"
    echo "[+] Binaire créé → ./copy_fail"
    echo ""
    echo "Pour lancer plus tard : ./run.sh"
    ls -lh copy_fail 2>/dev/null || true
else
    echo "[-] Erreur lors de la compilation."
    exit 1
fi

echo "========================================"
echo "          Compilation terminée          "
echo "========================================"
