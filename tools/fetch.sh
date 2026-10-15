#!/usr/bin/env bash
# Usage (WSL): tools/fetch.sh <google-drive-or-direct-url> <dest-dir>
# Downloads a challenge file (Drive link or direct URL), handles Drive's large-file virus-scan
# interstitial via gdown, then reports size and FLAGS anything big before it ever reaches git.
set -e
url="$1"; dest="${2:-.}"
mkdir -p "$dest"
cd "$dest"

if [[ "$url" == *drive.google.com* || "$url" == *"docs.google.com"* ]]; then
  echo "[fetch] Google Drive link detected - using gdown (handles large-file scan bypass, folders too)"
  if [[ "$url" == *"/folders/"* ]]; then
    ~/ctfenv/bin/gdown --folder "$url" -O .
  else
    ~/ctfenv/bin/gdown "$url" -O ./
  fi
else
  echo "[fetch] direct URL - using wget"
  wget -q --content-disposition "$url"
fi

echo "--- downloaded files ---"
for f in $(find . -maxdepth 2 -type f); do
  sz=$(stat -c%s "$f")
  hsz=$(numfmt --to=iec "$sz")
  flag=""
  if   [ "$sz" -gt 104857600 ]; then flag="  !!! OVER 100MB - GitHub HARD BLOCKS this, do not git add as-is (use git-lfs, external share, or .gitignore it and note the Drive link instead)"
  elif [ "$sz" -gt 52428800 ]; then flag="  !! over 50MB - GitHub will warn; consider git-lfs or keeping it out of the repo"
  fi
  printf '%-50s %10s%s\n' "$f" "$hsz" "$flag"
done
