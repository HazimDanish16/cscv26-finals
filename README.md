# CSCV26 Finals - team workspace

Shared workspace for the finals (9am-5pm). Both teammates' Claude Code agents read `CLAUDE.md`
automatically when opened in this repo - that's the shared playbook (tools, flag-verification
rules, brute-force policy, writeup workflow). This README is for the humans setting it up.

## First time on a new machine
1. Clone this repo.
2. Inside WSL (Ubuntu distro), from the repo root: `bash tools/setup_wsl.sh`
   - Installs everything that doesn't need sudo (python venv + libs, Ghidra, pwndbg source,
     jwt_tool, CUPP, libc-database, wordlists).
   - Prints two commands you need to run yourself (pwndbg's own setup.sh, and an apt install) -
     both need your sudo password interactively.
3. Make sure Docker Desktop is running with WSL integration enabled for your distro.
4. That's it - CLAUDE.md in this repo tells your agent what everything does.

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
