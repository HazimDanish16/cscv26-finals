# CSCV26 Finals - team workspace

Shared workspace for the finals (9am-5pm). Both teammates' Claude Code agents read `CLAUDE.md`
automatically when opened in this repo - that's the shared playbook (tools, flag-verification
rules, brute-force policy, writeup workflow). This README is for the humans setting it up.

## First time on a new machine
Assumes a WSL **Ubuntu 24.04** distro (`wsl --install -d Ubuntu` if you don't have one yet).
1. Clone this repo.
2. Install Docker Desktop for Windows if you don't have it, and enable WSL integration for your
   Ubuntu distro (Docker Desktop > Settings > Resources > WSL Integration). Can't be scripted
   from inside WSL - do this first, manually.
3. Inside WSL (Ubuntu distro), from the repo root, run the **sudo apt command** that
   `tools/setup_wsl.sh` prints (do this before step 4 - some no-sudo steps depend on
   `python3-venv` being installed).
4. Then run `bash tools/setup_wsl.sh` itself - installs everything that doesn't need sudo
   (python venv + libs, Ghidra, pwndbg source, jwt_tool, CUPP, libc-database, wordlists), and
   checks Docker is reachable. Safe to re-run if anything was skipped.
5. Finally run `cd ~/pwndbg && ./setup.sh` (its own interactive sudo prompt).
6. That's it - CLAUDE.md in this repo tells your agent what everything does.

If your WSL distro isn't Ubuntu 24.04, some apt package names (radare2, tesseract-ocr) may not
resolve the same way - the script will tell you which ones failed.

## During the competition
- Claim a challenge by adding/editing its row in `challs/INDEX.md` before starting, so you two
  don't duplicate work.
- Each challenge lives in `challs/<name>/` with its files, scripts, and eventually `writeup.md` +
  `solve.py`/`solve.sh` (written the moment a flag is confirmed correct - see CLAUDE.md's
  writeup workflow).
- Push as you go. Anything not pushed is invisible to your teammate's agent.
- Only what's actually committed is shared - if you've been going back and forth with your
  agent and haven't pushed, your teammate's agent has no idea any of that happened.

## Flags
- Tools print findings as `CANDIDATE (unverified)` - a planted decoy is common, verify the
  mechanism before trusting one (see CLAUDE.md).
- Don't submit to the scoreboard without checking with each other first (avoid wasted attempts
  on a decoy, or racing each other on the same flag).
