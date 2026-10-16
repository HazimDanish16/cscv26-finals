# REV02 handoff (2026-10-16)

Status: **unsolved; no verified flag candidate**. The 32,400,194-byte local `dl/phantom.rar` matches the published SHA-256 and contains only `phantom.exe.html`, an 866 MB IDA listing. Keep `dl/` and `ex2/` out of Git.

## Confirmed findings

- Main is `sub_140002FA0`. It parses exactly 64 hex characters to 32 bytes, calls `sub_140001780`, then branches on its low-byte return. The branch is hidden by overlapping instructions at `0x1400038C9`: `jmp +1; test al, al; jz 0x1400039B3`; that target leads to the `wrong` print at `0x1400039BC`. The `correct!` path is conditional.
- `sub_140001780` returns the result of `sub_140031E70` on its live path. At `0x14004524C..0x140045280`, the latter tests `((qword_1406D2070 * 255) XOR qword_1406D2090) == 0xCAFEBABE133713C8`. One error path returns zero.
- Code at `0x1400DE470` sets `qword_1406D2090` using `byte_1406D20C0` and `qword_1406D2070`; code at `0x1400DE4D0` sets `qword_1406D2070` from four `.rdata` qwords. If the named byte remains zero, success requires `qword_1406D2070 == 1`. The static, unmodified four-qword calculation gives `0x00A9A2606C024D42`, so code or data mutation upstream is unresolved.
- A 2,716-byte code island at `0x14005AD14..0x14005B7B0` was recovered from IDA `db`/`dq` directives to `hidden_code.bin`; `hidden_code.asm` is its Capstone disassembly. It uses executable allocation, thread creation, page protection changes, and a code XOR helper at `0x1400DE550`. This confirms that static listing order is insufficient to settle runtime behavior.

## Local tools and artifacts

- `notes.md`: full investigation, addresses, and earlier findings.
- `unpack_ida_data.py`: recover contiguous `db`/`dw`/`dd`/`dq` bytes; its one manual six-byte patch is documented in source.
- `hidden_code.bin` / `hidden_code.asm`: recovered island and disassembly.
- `asm_probe.py`: Keystone feasibility probe. Run in WSL: `~/ctfenv/bin/python asm_probe.py /tmp/phantom.txt 140001780 140002920`. Result for the checker: 833 matched lengths, 12 length gaps, 0 encoding failures across 845 instructions. For `140031E70 14004533D`: 10,915 matched, 83 length gaps, 10 failures across 11,008 instructions. Length gaps often reflect `db` bytes between instructions; they are not all errors.
- `rebuild_text.py`: best-effort full `.text` assembler; the first full run was deliberately interrupted to save usage and has **not produced a validated image**. It is slow. Review and optimize it before depending on its output.
- The prior analyst's WSL files still exist: `/tmp/phantom.txt` (text listing), `/tmp/fnidx.txt` (function index), `/tmp/rdata.bin` (5.8 MB recovered `.rdata`). Helpers `fn.py` and `mods.py` use `/tmp/phantom.txt`.

## Next work

1. Trace the runtime writes or code patches that affect `qword_1406D2070`, `qword_1406D2090`, or the four qwords at `.rdata:0x1406BAFD0..0x1406BAFE8`.
2. If using emulation, validate reconstructed instruction bytes at every taken branch before trusting the check result. The raw-code islands and overlapping instructions must be preserved, and Windows API calls need stubs.
3. Derive and verify the 32-byte input before treating any text as a flag. Nothing here supports a submission yet.
