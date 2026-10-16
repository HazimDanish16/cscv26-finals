#!/home/jimmy/ctfenv/bin/python
"""Minimal API client for jeo.cscv.vn (CSCV2026 Finals - NOT CTFd, custom SvelteKit platform).
Auth: Authorization: Bearer <token> - token comes from localStorage after team-token login
(secrets/jeo_session_token.txt), captured via Claude-in-Chrome, NOT from the original team
login token (secrets/jeo_token.txt - that's exchanged for this session token at login time).
Base API: https://jeo.cscv.vn/api/v2/ . Error shape: {"kind": "...", "message": "..."}.

Usage:
  jeo_api.py challs                   list all challenges (VERIFIED - full description/points/
                                       category/instancer-flag all come back in this one call,
                                       no separate per-challenge detail endpoint needed)
  jeo_api.py start <id>                start/get the challenge's instance (VERIFIED: PUT
                                       .../integrations/challs/<id>/instance - captured from the
                                       real "Start instance" button click)
  jeo_api.py status <id>                poll instance status (VERIFIED: GET same path)
  jeo_api.py submit <id> <flag>        submit a flag (UNVERIFIED GUESS at /challs/<id>/submit -
                                       could not confirm the real path without risking a wasted
                                       submission; VERIFY THE RESPONSE CAREFULLY on first real use,
                                       and watch the Network tab if it looks wrong)
  jeo_api.py raw <method> <path> [json]  arbitrary call to any other /api/v2/<path>

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
    elif cmd == 'start':
        status, body = req('PUT', f'integrations/challs/{sys.argv[2]}/instance')
    elif cmd == 'status':
        status, body = req('GET', f'integrations/challs/{sys.argv[2]}/instance')
    elif cmd == 'stop':
        status, body = req('DELETE', f'integrations/challs/{sys.argv[2]}/instance')
    elif cmd == 'submit':
        status, body = req('POST', f'challs/{sys.argv[2]}/submit', json={'flag': sys.argv[3]})
    elif cmd == 'raw':
        method = sys.argv[2] if len(sys.argv) > 3 else 'GET'
        path = sys.argv[3] if len(sys.argv) > 3 else sys.argv[2]
        body_json = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
        status, body = req(method, path, json=body_json)
    else:
        print(__doc__)
        return
    print(f'HTTP {status}')
    print(json.dumps(body, indent=2) if isinstance(body, (dict, list)) else body)


main()
