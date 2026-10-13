#!/usr/bin/env bash
# ForgeKit kurulum betiği — "forgekit" komutunu her yerden çalıştırılabilir yapar.
#
# Kullanım:
#   cd forgekit
#   sudo ./install.sh
#
# Bundan sonra uçbirimin HER YERİNDEN:
#   forgekit            (normal kullanıcı yetkisiyle)
#   sudo forgekit        (root yetkisiyle, bazı araçlar — ör. gobuster'ın
#                          bazı modları — root ile daha rahat çalışabilir)
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Bu betiği 'sudo ./install.sh' ile çalıştırın (sistem genelinde komut kurmak için gerekli)."
    exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/forgekit"
BIN_PATH="/usr/local/bin/forgekit"

echo "[*] Dosyalar kopyalanıyor: $SRC_DIR -> $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp "$SRC_DIR/recon.py" "$INSTALL_DIR/recon.py"
cp "$SRC_DIR/menu.py" "$INSTALL_DIR/menu.py"

echo "[*] Komut oluşturuluyor: $BIN_PATH"
cat > "$BIN_PATH" <<EOF
#!/usr/bin/env bash
cd "$INSTALL_DIR" || exit 1
exec python3 menu.py "\$@"
EOF
chmod +x "$BIN_PATH"

echo ""
echo "[+] Kurulum tamamlandı."
echo "    Artık her yerden şu şekilde çalıştırabilirsiniz:"
echo "        forgekit"
echo "        sudo forgekit"
echo ""
echo "    Dosyalar şurada tutuluyor: $INSTALL_DIR"
echo "    Güncelleme yapmak isterseniz bu klasördeki recon.py/menu.py'yi"
echo "    değiştirip tekrar 'sudo ./install.sh' çalıştırmanız yeterli."
