import socket
import sys

HOST = "127.0.0.1"
PORT = 1337

def raw_request(path, method="GET", extra_headers="", body=b""):
    req = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra_headers}"
    if body:
        req += f"Content-Length: {len(body)}\r\n"
    req += "\r\n"
    data = req.encode("latin-1") + body
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(data)
    resp = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    s.close()
    return resp

def status_of(resp):
    try:
        line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return line
    except Exception:
        return repr(resp[:50])

word = "office"
hexmap = {c: f"%{ord(c):02x}" for c in word}

paths = []
for i in range(len(word)):
    enc = word[:i] + hexmap[word[i]] + word[i+1:]
    paths.append(f"/{enc}/process")

# also try encoding 2 chars, and uppercase hex
for i in range(len(word)):
    enc = word[:i] + hexmap[word[i]].upper().replace("%", "%") + word[i+1:]
    paths.append(f"/{enc}/process")

for p in paths:
    resp = raw_request(p)
    print(f"{p!r:40} -> {status_of(resp)}")
