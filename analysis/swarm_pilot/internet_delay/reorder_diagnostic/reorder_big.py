import socket, threading, time, sys
exec(open("/r.py").read().split("def serve")[0])
BIG = b"y" * (40 << 20)
def serve():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 8091)); s.listen(64)
    while True:
        c, _ = s.accept(); c.recv(100); c.sendall(BIG); c.close()
threading.Thread(target=serve, daemon=True).start(); time.sleep(0.2)
b0 = counters(); t = time.time()
for _ in range(5):
    c = socket.create_connection(("127.0.0.1", 8091)); c.sendall(b"GET"); n = 0
    while True:
        d = c.recv(1 << 20)
        if not d: break
        n += len(d)
    c.close()
b1 = counters(); print(sys.argv[1], "5 x 40 MB replies", round(time.time() - t, 2), "s", {k: b1[k] - b0[k] for k in b0})
