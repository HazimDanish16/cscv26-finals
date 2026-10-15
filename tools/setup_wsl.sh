#!/usr/bin/env bash
# One-shot environment bootstrap for a new machine/teammate. Run inside WSL (Ubuntu), from the repo root:
#   bash tools/setup_wsl.sh
# Safe to re-run - skips anything already present. Splits into no-sudo (runs automatically)
# and sudo (prints the command for you to run yourself) sections.
set -e
echo "== python venv + pip packages (no sudo) =="
python3 -m venv ~/ctfenv 2>/dev/null || true
~/ctfenv/bin/pip install -q --upgrade pip
~/ctfenv/bin/pip install -q pwntools pycryptodome z3-solver gmpy2 capstone ropper ROPGadget \
  requests beautifulsoup4 pyjwt flask-unsign angr pillow base58 ctf-dl volatility3 unicorn gdown

echo "== repo clones (no sudo) =="
cd ~
[ -d jwt_tool ]       || git clone -q https://github.com/ticarpi/jwt_tool.git
[ -d cupp ]           || git clone -q https://github.com/Mebus/cupp.git
[ -d libc-database ]  || git clone -q https://github.com/niklasb/libc-database.git
[ -d pwndbg ]         || git clone -q https://github.com/pwndbg/pwndbg.git
~/ctfenv/bin/pip install -q -r ~/jwt_tool/requirements.txt 2>/dev/null || true

echo "== wordlists (no sudo) =="
mkdir -p ~/wordlists
[ -f ~/wordlists/jwt-secrets.txt ] || wget -q -O ~/wordlists/jwt-secrets.txt \
  https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
ls /usr/share/wordlists/rockyou.txt >/dev/null 2>&1 || echo "  !! rockyou.txt not found - it's usually bundled with seclists/kali wordlists apt package, or: gunzip /usr/share/wordlists/rockyou.txt.gz if present, else download manually"

echo "== Ghidra (no sudo, needs java 17+) =="
if [ ! -d ~/ghidra ]; then
  wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip -O /tmp/ghidra.zip
  unzip -q /tmp/ghidra.zip -d ~ && mv ~/ghidra_* ~/ghidra && rm /tmp/ghidra.zip
fi

echo
echo "== pwndbg setup (interactive - runs its own sudo prompt, do this yourself) =="
echo "   cd ~/pwndbg && ./setup.sh"
echo
echo "== packages needing sudo - run this yourself =="
echo "   sudo apt update && sudo apt install -y radare2 nmap jq john sqlmap gobuster ffuf socat ltrace \\"
echo "     tesseract-ocr zbar-tools poppler-utils nodejs default-jre golang gdb-multiarch ruby-full \\"
echo "     qemu-user qemu-user-static patchelf libfplll-dev libgmp-dev apktool default-jdk-headless \\"
echo "     wordlists  # (wordlists package provides /usr/share/wordlists/rockyou.txt on most distros)"
echo "   sudo gem install zsteg one_gadget"
echo
echo "== Docker =="
echo "   Make sure Docker Desktop is running with WSL integration enabled for this distro"
echo "   (Docker Desktop Settings > Resources > WSL Integration)."
echo
echo "Done with the no-sudo parts. Run the two commands printed above to finish."
