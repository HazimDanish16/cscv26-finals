# MISC03 (misc, 500pts)

id: `misc03`

instancer: False

## Description

[magic_bug.apk](https://files.59.153.245.189.sslip.io/MISC03-621719b9a72b62004692d44d/magic_bug.apk)  
SHA-256: `780af5e1f78f24fc0fe60610abf3ddaf9708917fb2930fe86d3157574acf9ef2`

Do you really think a shield is unbreakable?

**Part 1** — Break through the app's protection, bypass its security checks, and uncover the first flag. But breaking the shield is only the beginning...

**Part 2** — Follow the app's API traffic and find the flaw hidden behind the server's trust. Some bugs are obvious. This one feels more like magic.

Flag: `CSCV2026{sha256sum(CSCV2026{xxx}CSCV2026{yyy})}` — flag1 (Part 1) and flag2 (Part 2) are the full `CSCV2026{...}` flags, concatenated with nothing in between (no newline); lowercase hex.
