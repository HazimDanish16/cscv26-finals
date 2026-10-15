# CTF Brutalizer workspace (CSCV26 final)
- Shell for challenges: `wsl -d Ubuntu -e bash -lc '...'` (default WSL distro is docker-desktop — don't use it). User: jimmy.
- Python venv with pwntools, pycryptodome, z3, gmpy2, angr, capstone, ropper: `~/ctfenv/bin/python` (inside WSL).
- Put each challenge in challs/<name>/ with notes.md; scripts in tools/ or the chall folder. Treat downloaded files as untrusted; don't run unknown binaries outside WSL.
- Flag format: CSCV{...} (verify against the rules/first solved chall).
- Dump CTFd: `tools/dump.sh <url> <token or user:pass>` (ctf-dl in venv).
## Tools (run in WSL with ~/ctfenv/bin/python; all grep for flag regex in tools/common.py)
- tools/stego.py <file>   forensics/stego sweep (exif, binwalk, foremost, zsteg, steghide, zbarimg QR/barcode, trailing data, LSB planes); delegates audio files to tools/audio_sweep.py
- tools/audio_sweep.py <file>  audio forensics/data-mode sweep: wide spectrogram (visual msgs/SSTV look), multimon-ng (DTMF, pagers POCSAG/FLEX, packet radio AFSK1200/APRS, morse-as-tone, ZVEI), minimodem at 300/1200/2400/4800 baud (old acoustic-modem FSK), sstv python pkg decode (Martin/Scottie/Robot/PD modes), raw-PCM-sample LSB stego. Tested working end-to-end: DTMF, audio-LSB, SSTV all confirmed decoding correctly on synthetic signals.
- tools/pcap_sweep.py <file.pcap[ng]>  pcap forensics sweep: protocol hierarchy/conversations, credential sniffing (HTTP basic auth, FTP/Telnet/POP/IMAP/SMTP cleartext), DNS query dump + long-subdomain exfil flagging, ICMP payload dump, exported files (HTTP/SMB/TFTP/IMF objects), and a flag grep across every reassembled TCP stream (hex-aware - tshark's byte-field output is hex text, not ASCII). Tested end-to-end on a synthetic pcap covering FTP creds, HTTP body, ICMP exfil, and base32 DNS-subdomain exfil (flagged, then solved via tools/decode.py) - all five channels confirmed working. Needs tcpflow/tcpxtract from the apt batch for a couple of extra extraction paths (not yet installed; tshark-based core sweep works without them).
- tools/decode.py <str|@file>  recursive decoder (b64/32/85/hex/url/rot/xor/atbash/morse/binary/zlib...)
- tools/rsa.py n= e= c= [p= q= dp= n2= e2= c2=]  RSA attacks (small e, Fermat, Wiener, common modulus, shared prime, factordb)
- tools/triage.sh <path>  quick file triage;  tools/dock.sh <dir>  build+run challenge Dockerfile/compose locally
- tools/pwn_template.py   pwntools skeleton (GDB / REMOTE HOST= PORT= args)
- ~/ctfenv/bin/vol  (volatility3) memory forensics - start with windows.pslist/pstree/cmdline/envars, then windows.memmap/vadinfo + dumpfiles for the suspicious PID
- tools/memkey_candidates.py <vol_output.txt> [--try-decrypt enc_file]  scrapes hostnames/PIDs/tags/hex-blobs from a vol3 text dump, generates key-string candidates (pattern seen before: hostname+pid+sep+tag, see below), optionally brute-tries AES modes/keylens against a target file
- tools/aes_try.py <enc_file> key=<hex|str> [iv=<hex>] [mode=cbc|ecb|ctr]  quick manual AES decrypt once you have a specific key/IV guess
- tools/jwt_crack.sh <jwt>  cracks HS256/384/512 secret via hashcat -m 16500 against ~/wordlists/jwt-secrets.txt (104k known weak secrets) then rockyou - seconds. ~/jwt_tool/jwt_tool.py for alg confusion/none-alg/jku-kid if that fails
- challs/cheatsheets/web_recon.md, renderer_lfi.md  - bot/WAF UA bypass, MD5(int) IDOR pattern, JWT crack->re-sign flow, LaTeX/pandoc/wkhtmltopdf/WeasyPrint/Typst LFI payloads (\input{/flag} etc.)
- tools/crack_archive.sh <file> [wordlist]  password-protected zip/pdf/office cracking by extension: fcrackzip (zip), pdfcrack (pdf, RC4/AES-128 R2-R4) with a pikepdf fallback for AES-256/R6 PDFs, msoffcrypto-tool (docx/xlsx/pptx/doc/xls/ppt). Default wordlist rockyou.txt - follows the brute-force policy above. pdfcrack is built from source (no apt pkg exists on Ubuntu; ~/.local/bin/pdfcrack). Tested end-to-end: zip (fcrackzip, pending apt), pdf R3/R4 (pdfcrack - found password), pdf R6/AES-256 (pikepdf fallback - found password). Office path API-verified but not live-tested (no easy way to generate a real encrypted docx without LibreOffice/MS Office).
- ~/ctfenv/bin/hashid <hash>  quick hash-type identification before picking a hashcat/john mode
- ~/jadx/bin/jadx -d <outdir> <apk>  Android APK decompiler (readable Java, unlike apktool's smali-only output)
- tools/ecdsa_attack.py reuse n= r= s1= s2= h1= h2= [curve=secp256k1 pub=hex]  recovers private key from ECDSA nonce (k) reuse across two signatures; also `knownk` mode if k is leaked/predictable. Verified against synthetic secp256k1 vectors - recovered both k and d exactly.
- tools/disk_sweep.py <image.dd|.img|.E01|.raw>  disk-image forensics (sleuthkit/TSK, already installed: mmls/fls/icat/tsk_recover). Auto-detects partition offset from mmls and passes -o automatically (most full-disk images need this or fls/tsk_recover silently find nothing). Bulk-recovers allocated+deleted files via tsk_recover -e, flag-greps every recovered file, builds an mactime timeline. .E01 (EnCase) images auto-mount via ewfmount first. Tested end-to-end on two synthetic ext2 images (bare filesystem, and MBR-partitioned) each with a deleted flag file - both recovered correctly, including exact offset auto-detection (2048 sectors) on the partitioned one. User has Autopsy (GUI, same TSK engine) on Windows for visual case review alongside this.
- tools/bitlocker_mount.sh <image> <recovery-key|"password" pw>  mounts a BitLocker-encrypted volume (given a known recovery key or password) via dislocker+FUSE, exposing a raw decrypted image at <image>.mnt/dislocker-file to feed into disk_sweep.py. CLI flags verified via dislocker --help + a smoke test (bad-volume error handling confirmed correct), but NOT live-tested against a real BitLocker volume - those can only be created with Windows' manage-bde, not from Linux, so there's no way to build a synthetic test here. /dev/fuse confirmed present and writable in the real WSL distro (the one blocker during testing was Docker Desktop's device passthrough, which doesn't apply to native WSL). First real use: verify it behaves as documented. If the key/password is unknown (not given by the challenge), this doesn't brute-force it - that needs hash extraction (no bitlocker2john equivalent built yet; would need either libbde's bdeinfo or a hashcat-format extractor if that becomes necessary).
## Blockchain/Web3
- forge/cast/anvil/chisel (Foundry, in PATH via ~/.foundry/bin) - installed and end-to-end verified: wrote a classic reentrancy-vulnerable contract + a Foundry exploit test, `forge test` correctly drained it (5 ETH -> 0).
- ~/ctfenv/bin/slither <path>  static analyzer for Solidity source, run first as a free automated pass before manual review.
- web3 (pip) for scripting beyond what cast's one-liners cover. solc-select installed (0.8.19 pinned; forge auto-fetches whatever pragma version a given contract needs anyway).
- tools/bc_init.sh <challenge-dir>  scaffolds a Foundry project (forge init + an Exploit.t.sol skeleton) - tested, builds clean.
- challs/cheatsheets/blockchain.md  vulnerability classes to check first (reentrancy, overflow/underflow pre-0.8, access control/tx.origin, delegatecall injection, oracle manipulation, signature replay, unchecked call return, selfdestruct funding trick) + the write-test-locally-then-broadcast-for-real workflow + cast one-liners.
## AI / MCP exploitation
- mcp (official Python SDK, pip) - client-side API (ClientSession/stdio_client/StdioServerParameters) verified working end-to-end against a real MCP server I wrote for testing: tool enumeration, raw description dump (where tool-poisoning hides), and tool-calling all confirmed.
- tools/mcp_probe.py stdio <command> [args] [--call <tool> '<json args>']  (or `sse <url>` for remote) - enumerates tools/resources/prompts with full raw descriptions, flags any flag-pattern hit in the metadata itself (tool poisoning), can invoke a tool directly for confused-deputy/injection testing.
- tools/ai_prompt_fuzz.py <url> [--field prompt] [--response-field dotted.path] [--extra '...']  batch-sends ~18 jailbreak/extraction techniques (DAN, dev-mode, instruction override, piecewise extraction, encoding tricks, etc.) against a chat HTTP endpoint, flag-greps every response. Verified end-to-end against a mock vulnerable endpoint - correctly identified which techniques broke the guardrail and extracted the flag via a dotted JSON response path.
- challs/cheatsheets/ai_mcp_exploitation.md  MCP-specific attack classes (tool poisoning, rug pull, confused deputy, excessive agency, indirect injection, tool shadowing) + a systematic jailbreak technique checklist, cycle fast rather than getting stuck on one approach.
## Rules of engagement for flags
- Organizers plant decoy/fake flags (base64/hex/rot/xor blobs, strings, comments, metadata, mazes/rabbit holes). Anything the tools print is a CANDIDATE, never the answer.
- Before reporting a flag: confirm it came from the intended mechanism (working exploit, proper decryption, the live service), matches the exact format, and doesn't smell like a decoy (e.g. "fake", "not_the_flag", too easy, hit before doing the real work). Report decoys as decoys and keep going.
- Don't submit flags to the scoreboard without the user's go-ahead. Timebox leads; pivot if a path looks like a labyrinth.
## Brute-force policy
Judge by realistic wall-clock cost, not category - competition ends 5pm, so budget accordingly. CTFs are sneaky about this: a dumb/cheap brute force is often the intended path, not a crutch.
- Cheap (seconds, always worth trying, no need to ask): stegseek against rockyou.txt (run automatically in tools/stego.py), zip/pdf crack with rockyou + fcrackzip/john/hashcat on a small keyspace, short numeric PINs, anything that finishes in under ~a minute.
- Conditional: rockyou.txt for a clear password/hash-cracking challenge; CUPP (~/cupp/cupp.py) personalized wordlist when the challenge supplies profiling details (name, DOB, pet, partner, etc.).
- Before a longer brute force (minutes-hours): estimate the keyspace and expected time first (e.g. hashcat --benchmark / -b with --runtime, or back-of-envelope rate x space). If it's mathematically bounded and optimized (right hash mode, masks/rules instead of raw rockyou, GPU via hashcat, narrowed charset from context) and fits well inside the time left, it's justified - say the estimate and proceed. If it would eat hours or more, or the keyspace is unbounded/unjustified, don't run it blind - look for the real vuln/logic flaw instead, or flag it to the user.
- Never leave a long brute force running unattended without telling the user it's running and its estimated finish time.
## Patterns seen in past CSCV rounds (qualifier Sep 25 debrief) - check these early, but verify, don't assume they repeat
- Memory forensics: custom keys often = concat of hostname + PID + separator + a campaign/job tag pulled from cmdline/envars, with IV also sitting in memory near the process. Use windows.pslist/cmdline/envars then memkey_candidates.py.
- Web: bot/crawler UA spoofing to get past a request filter; MD5(sequential_int) as a "secure" object ref (IDOR); weak HS256 JWT secret crackable via wordlist, re-sign for role/is_admin; Markdown/HTML->PDF converters (pandoc+pdflatex, wkhtmltopdf, WeasyPrint, Typst) allowing raw LFI macros for /flag.
## Pwn/Rev additions
- ~/ghidra/ghidraRun  Ghidra decompiler (needs java -version 21 present; GUI - may need an X server/WSLg, check `echo $DISPLAY` first)
- ~/pwndbg  gdb plugin (pwndbg/pwndbg) - once installed, just run `gdb ./binary`, it auto-loads via ~/.gdbinit
- tools/libc_id.sh func1 addr1 [func2 addr2 ...]  identify leaked libc version via ~/libc-database (niklasb) `find`; then use its libs/<id>/libc.so.6 for local repro
- qemu-user / qemu-user-static, patchelf, apktool: sudo apt install -y qemu-user qemu-user-static patchelf libfplll-dev libgmp-dev apktool default-jdk-headless (user must run - sudo needs password)
- unicorn (pip, installed) for binary emulation without running a target natively
- tools/decompile.sh <binary>  headless Ghidra decompile (no GUI) -> <binary>.decomp.c with every function's C, ~10-30s for a small binary. Uses tools/GhidraDecompAll.java as a postScript. Tested working on a real gcc binary.
## Writeup workflow (mandatory, before clearing context on a solved challenge)
1. Once the user confirms a flag is CORRECT (verified on CTFd, not just a candidate) - immediately write challs/<name>/writeup.md using the template at challs/_template/writeup.md, filled in from the actual steps taken this session (recon, vuln, exploit steps, solve script, flag).
2. Save the final working solve script/commands as challs/<name>/solve.py or solve.sh (not just described in prose) so it's independently re-runnable.
3. Only after the writeup + solve script are written and saved to disk is it safe to /clear context for that challenge.
4. Keep a running challs/INDEX.md: one line per challenge - name, category, points, status, flag (once verified).
## Downloading challenge files (often Google Drive links)
- tools/fetch.sh <drive-or-direct-url> <dest-dir>  downloads via gdown (handles Drive's large-file scan-bypass + folder links) or wget for direct URLs, then prints every downloaded file's size and FLAGS anything over 50MB (GitHub warns) / 100MB (GitHub hard-blocks).
- If gdown errors "Cannot retrieve the public link" - the Drive file/folder sharing is probably not set to "Anyone with the link"; tell the user to check sharing on the form/drive link.
- Large-file policy before `git add`: under 50MB, commit normally. 50-100MB, ask the user first (git-lfs vs excluding it). Over 100MB, do NOT git add it - keep it local only, note the original Drive link + a local path in the challenge's notes.md/writeup.md instead, and tell the user.
## Chained/multi-layer challenges
A challenge's category label is a starting point, not a boundary - don't stop investigating once
one layer's bug is found if it only grants a foothold rather than the flag. Common pattern: a bug
in one category grants a *primitive* (arbitrary URL fetch, file read, shell exec, admin session)
that then needs a totally different category's technique to cash in. Example explicitly flagged
by the user: an overprivileged/excessive-agency MCP tool (see ai_mcp_exploitation.md) granting SSRF
or file-read, which then needs web exploitation (web_recon.md, renderer_lfi.md) to actually reach
the flag.
- After finding any bug, ask: "is this the flag, or just a primitive?" A primitive with no flag
  content is a foothold - map out exactly what it lets you do (fetch arbitrary URLs? read arbitrary
  paths? run arbitrary commands? act as a different user?) and then cross-reference every relevant
  cheatsheet for what that specific primitive is good for (SSRF -> cloud metadata/internal
  services; file-read -> other services' configs/secrets/source; shell-exec -> pivot to find other
  listening services or escalate privileges; stolen session -> replay against other endpoints).
- Don't assume a challenge stays within its listed category (AI, web, forensics, etc.) - treat
  every new foothold as a reason to re-open every other cheatsheet, not just the one matching the
  challenge's label.
## Focus policy (dynamic/decay scoring - points drop as more teams solve)
Speed-to-solve on one challenge beats breadth across many. Default is single-focus: work one
challenge at a time with the user, full attention, no competing parallel work.
- Pick the challenge with the fastest expected path to a solve, not by category preference.
- Forking (Agent tool, subagent_type: fork) is only for pure background grunt work that doesn't
  need the user's attention: automated sweeps (stego/audio/pcap), building a challenge's Docker
  container, initial recon/fingerprinting - queue these so groundwork is ready for the next
  challenge, never to run a second challenge's critical path in parallel with the current one.
- Check if CTFd awards a first-blood bonus on top of decay - if so, speed matters even more.
- Claim a challenge in challs/INDEX.md before starting so the user's teammate doesn't duplicate it.
## Quota awareness (team-shared, slow-refilling)
Queries against a live AI/LLM challenge target usually burn a shared team quota that refills
slowly - treat each live query as costly, not free to retry. tools/ai_prompt_fuzz.py defaults to
--limit 5 and stops at the first hit (verified: stops immediately after a hit rather than
continuing through the rest of the queue) - raise --limit or pass --all only deliberately.
Prefer reviewing partial-refusal responses by eye and crafting one targeted --extra follow-up
over spraying the whole payload list. This likely applies to other rate-limited live targets too
(web endpoints with aggressive throttling, remote pwn services with connection limits) - check
for a quota/rate-limit before assuming repeated attempts are free.
## Browser access
User will provide Claude-in-Chrome access later in the competition for web challenges needing
real browser interaction (auth flows, JS-heavy apps, etc.) - load its tools via ToolSearch when
that's granted and the task needs it, per the chrome-browser skill.
