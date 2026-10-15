#!/usr/bin/env bash
# One-shot environment bootstrap for a new machine/teammate, assuming a genuinely fresh
# Ubuntu 24.04 WSL distro (tested package list against ubuntu:24.04 - if your distro/version
# differs, apt package names may need adjusting). Run inside WSL (Ubuntu), from repo root:
#   bash tools/setup_wsl.sh
# Safe to re-run - skips anything already present. Splits into no-sudo (runs automatically)
# and sudo (prints the command for you to run yourself) sections.
set -e

echo "== Docker check =="
if ! command -v docker >/dev/null 2>&1; then
  echo "  !! docker not found in this WSL distro. Install Docker Desktop for Windows and enable"
  echo "     WSL integration for this distro (Docker Desktop > Settings > Resources > WSL"
  echo "     Integration > toggle this distro on). Cannot be scripted from inside WSL - do this"
  echo "     manually, then re-run this script to continue."
else
  docker version --format 'docker {{.Server.Version}}' 2>&1 | head -1 || \
    echo "  !! docker CLI found but engine not reachable - open Docker Desktop and wait for it to start"
fi

echo "== python venv + pip packages (no sudo) =="
python3 -m venv ~/ctfenv 2>/dev/null || echo "  !! python3-venv missing - run the sudo apt command below first, then re-run this script"
~/ctfenv/bin/pip install -q --upgrade pip
~/ctfenv/bin/pip install -q pwntools pycryptodome z3-solver gmpy2 capstone ropper ROPGadget \
  requests beautifulsoup4 pyjwt flask-unsign angr pillow base58 ctf-dl volatility3 unicorn gdown \
  checksec.py sstv hashid msoffcrypto-tool pikepdf

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
if ! ls /usr/share/wordlists/rockyou.txt >/dev/null 2>&1 && [ ! -f ~/wordlists/rockyou.txt ]; then
  echo "  rockyou.txt not found system-wide - downloading a copy to ~/wordlists/rockyou.txt"
  wget -q -O ~/wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
  echo "  NOTE: scripts/CLAUDE.md reference /usr/share/wordlists/rockyou.txt - if yours ended up in"
  echo "  ~/wordlists/rockyou.txt instead, either: sudo mkdir -p /usr/share/wordlists && \\"
  echo "  sudo cp ~/wordlists/rockyou.txt /usr/share/wordlists/rockyou.txt, or symlink it."
fi

echo "== Ghidra (no sudo, needs java 17+) =="
if [ ! -d ~/ghidra ]; then
  wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip -O /tmp/ghidra.zip
  unzip -q /tmp/ghidra.zip -d ~ && mv ~/ghidra_* ~/ghidra && rm /tmp/ghidra.zip
fi

echo "== jadx - Android/Java decompiler (no sudo, needs java 11+) =="
[ -d ~/jadx ] || (wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip -O /tmp/jadx.zip && unzip -q /tmp/jadx.zip -d ~/jadx && rm /tmp/jadx.zip)

echo "== pdfcrack - build from source (no sudo, needs gcc+make) =="
mkdir -p ~/.local/bin
if [ ! -x ~/.local/bin/pdfcrack ]; then
  [ -d ~/pdfcrack-src ] || (wget -q https://sourceforge.net/projects/pdfcrack/files/latest/download -O /tmp/pc.tar.gz && mkdir ~/pdfcrack-src && tar xzf /tmp/pc.tar.gz -C ~/pdfcrack-src --strip-components=1 && rm /tmp/pc.tar.gz)
  (cd ~/pdfcrack-src && make) >/dev/null 2>&1
  ln -sf ~/pdfcrack-src/pdfcrack ~/.local/bin/pdfcrack
fi
grep -q '.local/bin' ~/.bashrc || echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc

echo
echo "== packages needing sudo - run this FIRST (interactively, needs your password) =="
cat <<'APT'
   sudo apt update && sudo apt install -y \
     build-essential gdb binutils binwalk libimage-exiftool-perl steghide foremost file curl wget \
     tshark hashcat netcat-openbsd strace openssl p7zip-full unzip git ffmpeg sox \
     python3 python3-venv python3-pip \
     radare2 nmap jq john sqlmap gobuster ffuf socat ltrace tesseract-ocr zbar-tools poppler-utils \
     nodejs default-jre golang gdb-multiarch ruby-full \
     qemu-user qemu-user-static patchelf libfplll-dev libgmp-dev apktool default-jdk-headless \
     multimon-ng minimodem direwolf libsox-fmt-all tcpflow tcpxtract \
     fcrackzip testdisk ewf-tools afflib-tools dislocker libbde-utils fuse3
   sudo gem install zsteg one_gadget
APT
echo "   (tested resolvable against a clean Ubuntu 24.04 image; if your WSL is a different"
echo "   release, package names like 'radare2' or 'tesseract-ocr' may need an alternate repo)"
echo "   tshark's installer may prompt 'allow non-root users to capture packets' - say Yes if asked."
echo
echo "== pwndbg setup (interactive - its own sudo prompt, run this after the apt command above) =="
echo "   cd ~/pwndbg && ./setup.sh"
echo
echo "Done with the no-sudo parts. Run the commands printed above (apt first, then pwndbg) to finish."
echo "Then re-run this script once more if you skipped the venv step above due to missing python3-venv."
