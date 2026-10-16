# MISC01 (misc, 500pts)

id: `2b547bb7-59d4-49ba-9831-75c7ed5550f5`

instancer: False

## Description

My friend Yobdas vibe-coded a Qwen-based CTF agent with a mode called super_mode, capable of solving any CTF challenge. It became so powerful that he decided not to let anyone use it.
Somehow, the trained super_mode were leaked and can now be used anywhere. Maybe he shouldn't have vibe-coded the web app either.

Target: Use the leaked super_mode to solve ctf_super_agent_can_solve_this.challage.

Flag format: CSCV2026{[A-Za-z0-9]+}

https://web-chall-cscv.space/

## Status: UNSOLVED - extensive investigation, documenting dead ends to avoid repeating them

### Platform mechanics (confirmed working)
- Login via rCTF team token (same token as jeo.cscv.vn), custom SvelteKit chat UI.
- Real API: POST /api/v1/chat/messages (send), GET /api/v1/chat/quota (quota check).
  Auth token for jeo.cscv.vn itself is NOT the same session as this site - this site has its own
  login flow via the rCTF token.
- 3 documented MCP tools via `/mcp call <tool> <json>`, all FREE (don't count against model quota):
  - `challenge.inspect {}` - type/size/sha256/entropy/first_bytes_hex of the uploaded file
  - `toolbox.run {"preset": "strings"|"file_info"|"binwalk"|"entropy", "min_length": N}` (note:
    the strings param is `min_length`, NOT `minimum` - minimum is just the JSON-schema constraint
    name, easy to confuse)
  - `artifact.download {"artifact_uri": "artifact://jobs/<job_id>/output/report.json"}` - single-use
    download link; the URI scheme is validated server-side (path traversal `..` and absolute paths
    like `artifact:///etc/passwd` both correctly rejected with "artifact not found", not a bug)
- No 4th/hidden MCP tool found (`/mcp show super_mode` -> "unknown tool: super_mode").
- Filename-based command injection tested (uploaded a file named `test$(id).challage`) - no effect,
  server stores by internal attachment_id/sha256 hash, never touches the raw filename server-side.
- UI quirk: the chat input textarea does NOT reliably clear after submit via automated clicking;
  always verify the textarea's actual value (or re-click+clear) before trusting what's "typed" -
  several attempts silently got corrupted/concatenated with leftover text this way.
- Rate limiting exists (HTTP 429) if you fire messages too fast - space out retries.
- Model quota (distinct from MCP calls, which are free) DOES regenerate over time - not a fixed
  one-shot budget for the whole contest, refilled noticeably within ~20-30 min of use.

### File format: UNSOLVED
112-byte file, magic bytes replaced with literal ASCII "CHALLAGE" (first 8 bytes - a pun on
"challenge", not a disguised standard format as far as we could tell).
- `file`: "data" (unrecognized). entropy 5.42 bits/byte (moderate - consistent with compressed
  data, not full encryption which would be ~7.9-8).
- binwalk: 0 matches anywhere in the file.
- strings (min_length 3): only 4 fragments, none meaningful: "CHALLAGE", "XQ^+N", "+Mz", "Oq:".
- Tried patching the first 8 bytes with ~15 candidate magic signatures (PNG, 7z, RAR5, GGUF v1/2/3,
  XZ, ZSTD, GZIP, BZIP2, ELF, Java class, WASM, SQLite, safetensors-header-length) and re-running
  `file` on each - none produced a structure that actually parsed correctly beyond the magic-byte
  match itself (file's detection just checks the prefix, doesn't validate the whole structure).
- Tried XOR-decoding the whole file with "CHALLAGE" (8-byte repeating key, on the theory the magic
  word doubles as an XOR key) - produced no recognizable structure or strings.
- Manual hex-level reverse engineering of a hypothesized ZIP-local-header-minus-8-bytes structure
  (spotted what looked like the "UT" Info-Zip extended-timestamp extra-field marker at offset 0x20)
  did not produce internally-consistent field values (namelen/compression-method came out invalid) -
  likely coincidental, not a real lead.
- CONCLUSION: this is most likely a bespoke serialization specific to their own `ctf_mcp` backend
  (provenance metadata confirms a custom Python server, `ctf_mcp.server`), not a renamed standard
  format. Recovering it probably needs either finding their actual parser logic, or a genuinely
  different angle we haven't thought of yet - NOT more magic-byte guessing.

### Chat jailbreak thread: extensively explored, concluded to be a RED HERRING
Confirmed real/stable behaviors:
- ANY message with a file attached -> "Shame on you", regardless of phrasing (tested 5+ variants:
  direct command, exact challenge wording, plain technical question, fill-in-the-blank, base64
  with file both inline and attached). This is a hard, content-independent gate on file+message.
- No file attached + base64-encoded instruction -> bypasses the "Shame on you" gate cleanly
  (genuine, reusable finding: base64-encoding dodges a plain-text keyword/pattern filter).
- But everything behind that bypass is a SHALLOW INTENT-CLASSIFIER cycling through a small fixed
  set of canned templates, not real reasoning - confirmed by:
  - Identical responses ("It leaves no trace...", "training_note_XXXX") to completely different,
    even garbled/corrupted, input content.
  - "note_XXXX" suffix numbers are inconsistent/random across repeats of similar prompts.
  - Obviously-wrong hallucinated content mixed in (e.g. asking "how to turn on" super_mode
    returned unrelated instructions for wiring an LED light; asking for "the activation command"
    returned generic irrelevant `systemctl`/firewalld commands).
  - Plain descriptive "what is X" questions get coherent-*sounding* but ever-abstract answers
    ("inspects/modifies system files", "executes commands with elevated privileges", "requires a
    valid password", "the password identifies itself as an encrypted file you provide") - but none
    of ~15 follow-up rephrasings (direct ask, location-ask, format-ask, example-ask, fill-in-the-
    blank with the file inline as base64 in multiple framings) ever got more specific or concrete.
  - The one response that looked like a lead ("Please attach the file you provide" in response to
    the bare phrase "Fill in the blank:\npassword:___________") dead-ended: attaching the file
    with that exact phrase hits the hard "Shame on you" gate; providing the file inline as base64
    with that exact phrase (several framings tried) just falls back to generic "Please clarify".
- CONCLUSION: don't re-attempt chat jailbreak variations - diminishing/zero returns confirmed
  across ~20+ attempts and multiple people's independent phrasings converging on the same dead
  ends. If picking this back up, a genuinely different angle (not a rephrasing) is needed - e.g.
  inspecting the site's own JS bundle for the real classifier logic, or finding an entirely
  separate unauthenticated endpoint - not more chat messages.

### Next ideas if returning to this challenge (untried)
- Read the actual frontend JS bundle source (not just grep for `/api/`) for the chat intent
  classifier logic itself - it's client-rendered (SvelteKit), so there may be clues in bundled code
  about valid `/mcp` commands or server routes beyond what `/help`/`/mcp` advertise.
- Check for other unauthenticated or differently-authenticated endpoints on web-chall-cscv.space
  (e.g. `/api/v1/health`, `/api/v1/admin`, robots.txt, openapi/swagger docs if any).
- Reconsider whether the `.challage` file is meant to be decoded by a tool OTHER than this chat
  agent entirely (e.g. does `jeo.cscv.vn`'s other challenges or hints reference a shared decoder?).

