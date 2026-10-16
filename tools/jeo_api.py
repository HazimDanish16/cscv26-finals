#!/home/jimmy/ctfenv/bin/python
"""Minimal API client for jeo.cscv.vn (CSCV2026 Finals - NOT CTFd, custom SvelteKit platform).
Auth: Authorization: Bearer <token> - token comes from localStorage after team-token login
(secrets/jeo_session_token.txt), captured via Claude-in-Chrome, NOT from the original team
login token (secrets/jeo_token.txt - that's exchanged for this session token at login time).
Base API: https://jeo.cscv.vn/api/v2/ . Error shape: {"kind": "...", "message": "..."}.

Usage:
  jeo_api.py challs                 list all challenges (VERIFIED: path+auth confirmed working,
                                     got the expected "badNotStarted" response pre-contest)
  jeo_api.py chall <id>              get one challenge's detail (UNVERIFIED GUESS - path not seen
                                     for real yet, confirm against an actual challenge once visible)
  jeo_api.py submit <id> <flag>      submit a flag (UNVERIFIED GUESS - same caveat, and this is
                                     irreversible/rate-limited - do NOT trust blind, watch the
                                     first real response carefully before relying on it)
  jeo_api.py raw <path>               GET any other /api/v2/<path>

NOTE: session token may expire/rotate - if calls start 401ing, re-extract it from the browser's
localStorage('token') via Claude-in-Chrome (javascript_tool: localStorage.getItem('token')) and
overwrite secrets/jeo_session_token.txt.
"""
import sys, os, json, requests

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_PATH = os.path.join(HERE, '..', 'secrets', 'jeo_session_token.txt')
BASE = 'https://jeo.cscv.vn/api/v2'


def token():
    return open(TOKEN_PATH, encoding='utf-8').read().strip()


def req(method, path, **kw):
    r = requests.request(method, f'{BASE}/{path.lstrip("/")}',
                          headers={'Authorization': f'Bearer {token()}'}, **kw)
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return r.status_code, body


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else None
    if cmd == 'challs':
        status, body = req('GET', 'challs')
    elif cmd == 'chall':
        status, body = req('GET', f'challs/{sys.argv[2]}')
    elif cmd == 'submit':
        status, body = req('POST', f'challs/{sys.argv[2]}/submit', json={'flag': sys.argv[3]})
    elif cmd == 'raw':
        status, body = req('GET', sys.argv[2])
    else:
        print(__doc__)
        return
    print(f'HTTP {status}')
    print(json.dumps(body, indent=2) if isinstance(body, (dict, list)) else body)


main()
