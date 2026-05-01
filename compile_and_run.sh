#!/bin/bash
# compile_and_run.sh - Compile et exécute directement

echo "========================================"
echo "   CVE-2026-31431 - Copy Fail Exploit   "
echo "          Compilation & Execution       "
echo "========================================"

if [ ! -f "copy_fail.c" ]; then
    echo "[-] Erreur : copy_fail.c non trouvé !"
    exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
    echo "[-] gcc n'est pas installé."
    exit 1
fi

echo "[+] Compilation..."
gcc -O2 -static -o copy_fail copy_fail.c -lz -lpthread

if [ $? -ne 0 ]; then
    echo "[-] Erreur lors de la compilation."
    exit 1
fi

chmod +x copy_fail
echo "[+] Lancement de l'exploit..."
echo "========================================"

./copy_fail
