import socket, threading, time, sys
def counters():
    L = open("/proc/net/netstat").read().splitlines() + open("/proc/net/snmp").read().splitlines()
    v = {}
    for h, r in zip(L, L[1:]):
        a, b = h.split(), r.split()
        if len(a) == len(b) and a[0] == b[0] and a[0] in ("TcpExt:", "Tcp:") and not a[1].isdigit() and b[1].lstrip("-").isdigit():
            v.update(zip(a[1:], map(int, b[1:])))
    return {k: v.get(k) for k in ("RetransSegs", "TCPOFOQueue", "TCPSACKReorder", "TCPLossProbes", "TCPDSACKRecv")}
def serve():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 8091)); s.listen(64)
    while True:
        c, _ = s.accept()
        n = 0
        while n < 1 << 20:
            d = c.recv(1 << 16)
            if not d: break
            n += len(d)
        c.sendall(b"ok"); c.close()
threading.Thread(target=serve, daemon=True).start(); time.sleep(0.2)
b0 = counters(); data = b"x" * (1 << 20)
for _ in range(30):
    c = socket.create_connection(("127.0.0.1", 8091)); c.sendall(data); c.recv(2); c.close()
b1 = counters(); print(sys.argv[1], {k: b1[k] - b0[k] for k in b0})
