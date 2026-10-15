# Web recon quick checklist (from qualifier debrief patterns)

1. **Bot/WAF filter bypass first** if tools get blocked/odd responses:
   - `User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
   - Also try a normal modern browser UA, `X-Forwarded-For: 127.0.0.1`, no `User-Agent` at all.
   - Apply this header set to sqlmap/gobuster/ffuf too (`-H`/`--header`), not just manual curl.

2. **IDOR via predictable hash of sequential ID**: if doc/object refs are hashes, check whether they're
   `MD5(int)` / `SHA1(int)` / `MD5(int+salt-guess)` for small integer ranges (1..~1000) - cheap, script it.

3. **JWT**: dump token at jwt.io structure first (alg, claims). Then:
   - `tools/jwt_crack.sh <token>` (hashcat -m 16500, wallarm jwt-secrets list then rockyou) - seconds.
   - If that fails: `~/jwt_tool/jwt_tool.py <token> -t <url> -rc "role=admin"` for alg confusion / none-alg / jku-kid injection.
   - Once secret or bypass found, re-sign with elevated claims (role/is_admin/etc.) and replay.

4. **Renderer LFI/RCE**: see `renderer_lfi.md` once an admin/export/PDF feature is reached.

5. General: check `/robots.txt`, `/.git`, `/api`, source comments, and diff behavior for admin vs anon roles before assuming auth is the only gate.
