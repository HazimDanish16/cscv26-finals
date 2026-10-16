# REV02 (rev, 500pts)

id: `rev02`

instancer: False

## Description

[phantom.rar](https://files.59.153.245.189.sslip.io/REV02-ef5e82f9c788b4ee91b4af49/phantom.rar)  
SHA-256: `61dfe84c1941c33f5bac3bad08b3669ec5c06d1eba460a29edbbaf710b3d470b`

I'd made "web asm" ctf challenge. Just lil' stuff of "antidebug", enjoy it :3  
flag: flag{REDACTED}

## Findings (session 1)
- phantom.rar (7z can't unpack RAR5 here; Windows `tar.exe -xf` works) -> ONE file: phantom.exe.html, 866MB = IDA HTML disassembly export of phantom.exe (no PE binary given). Extracted to ex2/ (untracked, big - do not git add). Text-stripped copy at WSL /tmp/phantom.txt (314MB); rdata bytes rebuilt at /tmp/rdata.bin (VA 0x140114028 base).
- Rust x64 console exe. Imports: ReadConsoleW/WriteConsoleW, NtReadFile/NtWriteFile, VirtualProtect, Toolhelp32 Module32 (anti-debug), CreateFileMapping.
- Modules (src\*.rs): main, resolve (API hash resolve), strtab (djb2-hashed lookup + XOR'd strings, e.g. 'nTcREATEmAILSLOTfILE'=NtCreateMailslotFile ^0x20), svc, abi, loader, curve, sig, handshake, lattice, derive(KDF), digest, cipher. Function->module map: mods.py.
- Input/checker routine = sub_140001780 (heavily obfuscated: MBA, junk movs, opaque predicates `(x|1)&~1 <= x` always true); actual main is sub_140002FA0.
- 5.7MB .rdata (0x14011xxxx-0x1406B8xxx) is ~8.0 entropy, no wasm magic; sub_1400A4BB0 samples one byte every 0x8000 (…DC1 offsets) -> probably integrity/ballast. No plaintext wasm/flag found.
- No binary => can't run/debug; options: (a) manual static RE of loader/handshake/derive/cipher, (b) reassemble listing to bytes (keystone) + emulate in unicorn.

## Findings (session 1, part 2) - static RE of the listing
- Tools: fn.py (--index builds /tmp/fnidx.txt, then `fn.py <addr>` prints a function minus junk movs), mods.py (function->rust module map). Needs /tmp/phantom.txt (regenerate from ex2/phantom.exe.html by stripping tags + html.unescape).
- Real main = sub_140002FA0 (main.rs). Flow: read line from stdin (NtReadFile / ReadConsoleW) -> sub_140002920 parses it as EXACTLY 64 hex chars -> 32 bytes (else prints "Invalid format. Expected 64 hex chars.") -> sub_140001780(key32) -> prints "correct!".
- Strings in main are XOR 0x43: "correct!", "wrong", "Invalid format. Expected 64 hex chars.".
- Resolved the hidden branch in main: after `call sub_140001780` at 0x1400038BF, `xor ecx,ecx; jz 0x1400038C9` enters the middle of IDA's displayed `call` at 0x1400038C8. The overlapping bytes decode as `jmp +1; test al,al; jz 0x1400039B3`. At 0x1400039B3, `xor eax,eax; jz 0x1400039B8` reaches the `wrong` print at 0x1400039BC. Thus `correct!` is conditional on the low byte returned by `sub_140001780`; the listing's apparent unconditional path was an anti-disassembly trick.
- The live tail of `sub_140001780` returns the value from `sub_140031E70` in `rax` (a separate error path returns zero). The latter has one `retn`; its success path at 0x14004524C..0x140045280 computes `al = ((qword_1406D2070 * 255) XOR qword_1406D2090) == 0xCAFEBABE133713C8`, and otherwise returns zero. `qword_1406D2090` is set by code at 0x1400DE470 from `byte_1406D20C0` and `qword_1406D2070`. The only *named* write to that byte is zero at 0x140033671, though indirect writes remain possible. If it is zero at check time, the condition simplifies to `qword_1406D2070 == 1` (mod 2^64). `qword_1406D2070` is written at 0x1400DE4D0 from four `.rdata` qwords; its static unmodified value computes to `0x00A9A2606C024D42`, so the upstream mutation/control path needs tracing.
- Live attachment HEAD check on 2026-10-16: `phantom.rar` still reports 32,400,194 bytes and the September 9 last-modified date; the local archive has the published SHA-256. Public platform hints were not accessible from the archive URL.
- `sub_140031E70` passes `loc_1400DE470` to `sub_1400479E0` with values from `qword_1406D20D0 + qword_1406D2080` and `qword_1406D20E8` (0x14004405A..0x14004407C). The purpose of that call remains unconfirmed.
- `sub_1400479E0` has a hidden live code island at 0x14005AD14..0x14005B7B0, recorded as IDA `db`/`dq` directives. `unpack_ida_data.py` recovers its 2,716 bytes to `hidden_code.bin`; Capstone disassembly is in `hidden_code.asm` (507 instructions). The island allocates an executable 0x1000-byte region (`VirtualAlloc` signature at 0x14005B3AC..0x14005B3C6), writes code to it, creates a thread, changes page permissions (`VirtualProtect` signature at 0x14005B584..0x14005B59D), and waits for a handle. This supports runtime code mutation/anti-debug behavior. Recovering the island avoids reassembling those bytes, but it does not yet reveal the required 32-byte input.
- sub_140001780: most blocks guarded by opaque predicates ((x|1)&~1 <= x => always skipped) = decoys. Live path: PEB-walk API resolver by export-name hash (24 APIs, resolve.rs, hash fn sub_1400C04B0), then sub_1400A5870 (lattice.rs, 23k lines, mostly junk/obfuscated, takes the 24 resolved ptrs; likely the anti-debug engine), sub_1400D6760 = SHA-256 update (K table at 0x1401141B0.., state init by sub_1400C5DE0) over the 32-byte key, sub_14007E150 (derive), sub_140031E70 (svc.rs, 12k lines), then FNV-ish constant mixing.
- Globals dword_1406D2030/204C/2050/2064/20F0 are rolling "taint" states updated with a 9E3779B9 mixer in loader/sig/handshake/resolve code (anti-tamper: debugger/tamper changes later key material).
- curve.rs (sub_140067530) is custom bigint/field math with DEADBEEF-style constants, not a standard curve.
- 5.7MB high-entropy .rdata blob unexplained (maybe ballast, maybe encrypted payload); sub_1400A4BB0 samples 1 byte per 0x8000 of it.
- IDA red (c77) highlights are just IDA errors (sp-analysis failed / bad call targets) - NOT hints.
- Options to go further: (A) reassemble .text from the listing with keystone (installed in ~/ctfenv) + run in unicorn with PEB/API stubs to trace; (B) keep reading handshake/derive/cipher/sig by hand. Both are multi-hour. Also worth asking organizers/platform whether an updated attachment (real phantom.exe or the 'web asm' files) exists: the description talks about a "web asm" challenge but the archive only has an IDA listing.
