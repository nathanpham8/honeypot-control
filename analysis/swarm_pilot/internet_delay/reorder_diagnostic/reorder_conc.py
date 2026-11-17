import socket, threading, time, sys
exec(open("/r.py").read().split("threading.Thread(target=serve")[0])
threading.Thread(target=serve, daemon=True).start(); time.sleep(0.2)
b0 = counters(); data = b"x" * (1 << 20)
def worker():
    for _ in range(10):
        c = socket.create_connection(("127.0.0.1", 8091)); c.sendall(data); c.recv(2); c.close()
ts = [threading.Thread(target=worker) for _ in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
b1 = counters(); print(sys.argv[1], "concurrent x4", {k: b1[k] - b0[k] for k in b0})
