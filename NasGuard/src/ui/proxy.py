# NasGuard DSM 窗口的 CGI：经 Unix 套接字把请求转给守护进程，由守护进程校验 DSM 登录态
import http.client, json, os, re, socket, sys, urllib.parse

def out(code, body, ctype="application/json; charset=utf-8"):
    if isinstance(body, str):
        body = body.encode("utf-8")
    sys.stdout.buffer.write(("Status: %d\r\nContent-Type: %s\r\nCache-Control: no-store\r\n\r\n" % (code, ctype)).encode())
    sys.stdout.buffer.write(body)
    sys.stdout.flush()

SOCK = "/var/packages/NasGuard/var/nasguard.sock"


class UConn(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect(SOCK)


env = os.environ
q = urllib.parse.parse_qs(env.get("QUERY_STRING", ""))
a = (q.get("a") or [""])[0]
if not re.match(r"^[a-z]{1,20}$", a):
    out(404, '{"error":"not found"}'); sys.exit(0)
token = env.get("HTTP_X_SYNO_TOKEN") or (q.get("SynoToken") or [""])[0]
data = None
if env.get("REQUEST_METHOD", "GET") == "POST":
    n = int(env.get("CONTENT_LENGTH") or 0)
    data = sys.stdin.buffer.read(min(n, 65536)) if n else b"{}"
hdr = {
    "Content-Type": "application/json",
    "X-NG-Cookie": env.get("HTTP_COOKIE", ""),
    "X-NG-Token": token,
    "X-NG-Remote": env.get("REMOTE_ADDR", ""),
    "X-NG-Host": env.get("HTTP_HOST", ""),
}
try:
    c = UConn("localhost")
    c.request("POST" if data is not None else "GET", "/api/" + a, body=data, headers=hdr)
    r = c.getresponse()
    out(r.status, r.read())
except Exception as e:
    out(502, json.dumps({"error": "daemon", "msg": str(e)}))
