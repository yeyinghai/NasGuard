#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NasGuard: 群晖 DSM 登录监控、暴力破解自动封禁、Bark 推送、每日安全简报。"""
import shutil
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import http.client
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
import socketserver
from socketserver import ThreadingMixIn

VERSION = "0.1.2"
REPO = "yeyinghai/NasGuard"
PKG = "/var/packages/NasGuard"
VAR = os.environ.get("NASGUARD_VAR", PKG + "/var")

CONF = VAR + "/config.json"
BANS = VAR + "/bans.json"
EVENTS = VAR + "/events.log"
PUSHES = VAR + "/pushes.log"
GEOF = VAR + "/geo.json"
CHAIN = "NASGUARD"
SOCK = VAR + "/nasguard.sock"
STARTED = time.time()
AUTHLOG = "/var/log/auth.log"
CONNDB = "/var/log/synolog/.SYNOCONNDB"
MESSAGES = "/var/log/messages"

DEFAULTS = {
    "enabled": True,
    "bark_url": "",                # 例如 https://api.day.app/你的Key
    "bark_local": "auto",          # auto / on / off：推送地址的端口在本机监听时直连 127.0.0.1
    "group": "nas",
    "level": "timeSensitive",
    "sound": "",
    "threshold": 5,
    "window": 10,                  # 分钟
    "cooldown": 60,                # 同一 IP 告警冷却（分钟）
    "ok_merge": 30,                # 同一 IP + 用户 + 方式的登录成功，多少分钟内只记一次、推一次
    "lan_prefix": "192.168.",
    "notify_fail": True,
    "notify_ssh_ok": True,
    "notify_web_ok": True,
    "notify_lan_login": True,
    "geo": True,
    "ban_enabled": True,
    "ban_time": 10080,             # 分钟，0 = 永久
    "whitelist": "",
    "report_enabled": True,
    "report_hour": 9,
    "report_minute": 0,
    "hostname": "",
    "update_mirror": "auto",       # auto / direct / ghfast / ghproxy
    "notify_update": True,         # 发现新版本时推送一次
}

LOCK = threading.RLock()
STOP = threading.Event()


def log(*a):
    print(time.strftime("%F %T"), *a, flush=True)


# ---------------- 配置与持久化 ----------------
def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def cfg():
    c = dict(DEFAULTS)
    c.update(load_json(CONF, {}))
    return c


CFG = {}


def reload_cfg():
    global CFG
    CFG = cfg()


def hostname():
    h = CFG.get("hostname") or socket.gethostname()
    return h if h and h != "(none)" else "Synology"


def append_line(path, line, keep=20000):
    with LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        try:
            if os.path.getsize(path) > keep * 200:
                with open(path, encoding="utf-8") as f:
                    lines = f.readlines()[-keep // 2:]
                with open(path, "w", encoding="utf-8") as f:
                    f.writelines(lines)
        except Exception:
            pass


def read_lines(path, n=None):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        return lines[-n:] if n else lines
    except Exception:
        return []


def event(kind, ip, user="", via=""):
    if kind == "fail":
        STATS_CACHE.clear()
    append_line(EVENTS, "\t".join([str(int(time.time())), kind, ip, user, via]))


# ---------------- IP 工具 ----------------
def is_lan(ip):
    p = CFG.get("lan_prefix") or ""
    if p and ip.startswith(p):
        return True
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    if ip.startswith(("10.", "192.168.", "169.254.", "127.")):
        return True
    m = re.match(r"172\.(\d+)\.", ip)
    if m and 16 <= int(m.group(1)) <= 31:
        return True
    low = ip.lower()
    if low.startswith(("fe80:", "fc", "fd")) or low.startswith("::ffff:192.168."):
        return True
    return False


def whitelisted(ip):
    if is_lan(ip):
        return True
    for w in re.split(r"[\s,]+", CFG.get("whitelist") or ""):
        w = w.rstrip("*")
        if not w:
            continue
        if ip == w or (w.endswith((".", ":")) and ip.startswith(w)):
            return True
    return False


def valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        return True
    except Exception:
        return False


GEO_CACHE = {}


def geo(ip):
    if not ip:
        return "未知"
    if is_lan(ip):
        return "内网"
    if not CFG.get("geo", True):
        return "-"
    with LOCK:
        if not GEO_CACHE:
            GEO_CACHE.update(load_json(GEOF, {}))
        hit = GEO_CACHE.get(ip)
    if hit and time.time() - hit[0] < 7 * 86400:
        return hit[1]
    loc = "未知"
    try:
        url = "http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,isp" % urllib.parse.quote(ip)
        with urllib.request.urlopen(url, timeout=5) as r:
            j = json.loads(r.read().decode("utf-8"))
        if j.get("status") == "success":
            c, rg, ct, isp = j.get("country", ""), j.get("regionName", ""), j.get("city", ""), j.get("isp", "")
            if c == "中国":
                c = ""
            if ct == rg:
                ct = ""
            loc = " ".join(x for x in (c, rg, ct) if x) or "未知"
            if isp:
                loc += " · " + isp
            with LOCK:
                GEO_CACHE[ip] = [time.time(), loc]
                if len(GEO_CACHE) > 2000:
                    for k in sorted(GEO_CACHE, key=lambda k: GEO_CACHE[k][0])[:500]:
                        GEO_CACHE.pop(k, None)
                save_json(GEOF, GEO_CACHE)
    except Exception:
        pass
    return loc


# ---------------- Bark 推送 ----------------
def local_listening(port):
    hexport = ":%04X" % int(port)
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(f) as fh:
                next(fh)
                for line in fh:
                    parts = line.split()
                    if parts[1].endswith(hexport) and parts[3] == "0A":
                        return True
        except Exception:
            pass
    return False


def http_post(url, body, connect_ip=None, verify=True):
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    host = u.hostname
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    target = connect_ip or host
    if u.scheme == "https":
        ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
        sock = socket.create_connection((target, port), timeout=10)
        sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPSConnection(host, port, timeout=10)
        conn.sock = sock
    else:
        conn = http.client.HTTPConnection(target, port, timeout=10)
    hdr = {"Content-Type": "application/json; charset=utf-8", "Host": u.netloc}
    conn.request("POST", path, body=body, headers=hdr)
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, data


def send(kind, title, body):
    url = (CFG.get("bark_url") or "").strip()
    if not url:
        return False, "未填写 Bark 地址"
    payload = {"title": title, "body": body, "group": CFG.get("group") or "nas",
               "level": CFG.get("level") or "active"}
    if CFG.get("sound"):
        payload["sound"] = CFG["sound"]
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    mode = CFG.get("bark_local", "auto")
    tries = []
    if mode == "on" or (mode == "auto" and local_listening(port)):
        tries.append("127.0.0.1")
    tries.append(None)
    msg = ""
    ok = False
    for ip in tries:
        for verify in (True, False):
            try:
                st, resp = http_post(url, data, ip, verify)
                if st == 200 and '"code":200' in resp.replace(" ", ""):
                    ok = True
                    msg = "发送成功" + ("（本机直连）" if ip else "") + ("" if verify else "（未校验证书）")
                    break
                msg = "HTTP %s %s" % (st, resp[:200])
                break
            except ssl.SSLError as e:
                msg = "SSL: %s" % e
                continue
            except Exception as e:
                msg = str(e)
                break
        if ok:
            break
    append_line(PUSHES, "\t".join([time.strftime("%F %T"), kind, "ok" if ok else "fail", title,
                                   body.replace("\n", " ")]), keep=400)
    if not ok:
        log("推送失败:", msg)
    return ok, msg


def send_async(kind, title, body_fn):
    def run():
        try:
            send(kind, title, body_fn())
        except Exception as e:
            log("推送异常:", e)
    threading.Thread(target=run, daemon=True).start()


# ---------------- 防火墙 ----------------
def ipt(v6, *args):
    exe = "ip6tables" if v6 else "iptables"
    try:
        return subprocess.run([exe, "-w"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15).returncode
    except FileNotFoundError:
        return 127
    except Exception:
        return 1


def has_cmd(c):
    return any(os.access(os.path.join(p, c), os.X_OK) for p in os.environ.get("PATH", "").split(":"))


def fw_ensure():
    for v6 in (False, True):
        if v6 and not has_cmd("ip6tables"):
            continue
        if ipt(v6, "-n", "-L", CHAIN) != 0:
            ipt(v6, "-N", CHAIN)
        for parent in ("INPUT", "DOCKER-USER", "FORWARD"):
            if parent == "FORWARD" and ipt(v6, "-n", "-L", "DOCKER-USER") == 0:
                continue  # 有 DOCKER-USER 时挂在它上面即可
            if ipt(v6, "-n", "-L", parent) != 0:
                continue
            if ipt(v6, "-C", parent, "-j", CHAIN) != 0:
                ipt(v6, "-I", parent, "1", "-j", CHAIN)


def fw_sync(bans):
    """让 NASGUARD 链与封禁表一致。"""
    for v6 in (False, True):
        if v6 and not has_cmd("ip6tables"):
            continue
        want = [ip for ip in bans if (":" in ip) == v6]
        try:
            out = subprocess.run(["ip6tables" if v6 else "iptables", "-w", "-S", CHAIN],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15).stdout.decode()
        except Exception:
            out = ""
        have = set()
        for line in out.splitlines():
            m = re.match(r"-A %s -s (\S+?)(/32|/128)? -j DROP" % CHAIN, line)
            if m:
                have.add(m.group(1))
        for ip in have - set(want):
            ipt(v6, "-D", CHAIN, "-s", ip, "-j", "DROP")
        for ip in set(want) - have:
            ipt(v6, "-A", CHAIN, "-s", ip, "-j", "DROP")


def fw_clean():
    for v6 in (False, True):
        if v6 and not has_cmd("ip6tables"):
            continue
        for parent in ("INPUT", "DOCKER-USER", "FORWARD"):
            while ipt(v6, "-C", parent, "-j", CHAIN) == 0:
                if ipt(v6, "-D", parent, "-j", CHAIN) != 0:
                    break
        ipt(v6, "-F", CHAIN)
        ipt(v6, "-X", CHAIN)


def get_bans():
    with LOCK:
        b = load_json(BANS, {})
        now = time.time()
        live = {ip: exp for ip, exp in b.items() if not exp or exp > now}
        if len(live) != len(b):
            save_json(BANS, live)
        return live


def ban(ip, minutes=None, reason="auto"):
    if not valid_ip(ip) or (reason == "auto" and whitelisted(ip)):
        return False
    if minutes is None:
        minutes = int(CFG.get("ban_time", 1440))
    with LOCK:
        b = get_bans()
        if ip in b:
            return True
        b[ip] = 0 if minutes == 0 else time.time() + minutes * 60
        save_json(BANS, b)
        fw_ensure()
        fw_sync(b)
    event("ban", ip, "", reason)
    log("封禁", ip, minutes, "分钟")
    return True


def unban(ip):
    with LOCK:
        b = get_bans()
        if ip == "all":
            b = {}
        else:
            b.pop(ip, None)
        save_json(BANS, b)
        fw_sync(b)
    event("unban", ip)


def fmt_min(m):
    m = int(m)
    if m == 0:
        return "永久"
    if m >= 1440 and m % 1440 == 0:
        return "%d 天" % (m // 1440)
    if m >= 60 and m % 60 == 0:
        return "%d 小时" % (m // 60)
    return "%d 分钟" % m


# ---------------- 事件处理 ----------------
FAILS = {}      # ip -> [ts...]
ALERTED = {}    # ip -> ts
RECENT = {}     # 去重 key -> ts


def dedupe(key, sec=3):
    now = time.time()
    with LOCK:
        for k in [k for k, t in RECENT.items() if now - t > 30]:
            RECENT.pop(k, None)
        if key in RECENT and now - RECENT[key] < sec:
            return True
        RECENT[key] = now
    return False


def on_fail(ip, user, via):
    if not ip or not valid_ip(ip) or dedupe(("f", ip, user, via)):
        return
    event("fail", ip, user, via)
    now = time.time()
    win = int(CFG.get("window", 10)) * 60
    with LOCK:
        lst = [t for t in FAILS.get(ip, []) if now - t < win] + [now]
        FAILS[ip] = lst
        cnt = len(lst)
    if cnt == int(CFG.get("threshold", 5)):
        event("brute", ip, user, via)
    if cnt < int(CFG.get("threshold", 5)) or is_lan(ip):
        return
    banned = False
    if CFG.get("ban_enabled", True):
        banned = ban(ip)
    with LOCK:
        last = ALERTED.get(ip, 0)
        if now - last < int(CFG.get("cooldown", 60)) * 60:
            return
        ALERTED[ip] = now
    if not CFG.get("notify_fail", True):
        return
    bt = ("已自动封禁 " + fmt_min(CFG.get("ban_time", 1440))) if banned else "未封禁（白名单或未开启封禁）"
    title = "⚠️ %s %s 暴力破解" % (hostname(), via or "登录")
    send_async("fail", title, lambda: "%s（%s）在 %s 分钟内失败 %d 次，最近尝试用户：%s。%s" % (
        ip, geo(ip), CFG.get("window", 10), cnt, user or "-", bt))


OK_SEEN = {}


def on_ok(ip, user, via):
    if not ip or dedupe(("o", ip, user, via), 5):
        return
    # 有些客户端（脚本、监控、SFTP 面板）会反复新建 SSH 连接，合并成一次
    merge = int(CFG.get("ok_merge", 30)) * 60
    now = time.time()
    key = (ip, user, (via or "").upper())
    with LOCK:
        for k in [k for k, t in OK_SEEN.items() if now - t > max(merge, 60)]:
            OK_SEEN.pop(k, None)
        last = OK_SEEN.get(key)
        OK_SEEN[key] = now
    if merge and last is not None and now - last < merge:
        return
    event("ok", ip, user, via)
    if ip in ("127.0.0.1", "::1"):
        return
    if is_lan(ip) and not CFG.get("notify_lan_login", True):
        return
    v = (via or "").upper()
    if v in ("SSH", "SFTP"):
        if not CFG.get("notify_ssh_ok", True):
            return
        title = "🔐 %s SSH 登录成功" % hostname()
    elif v in ("DSM", "HTTP/HTTPS", "QUICKCONNECT", "WEB"):
        if not CFG.get("notify_web_ok", True):
            return
        title = "🌐 %s DSM 网页登录成功" % hostname()
    else:
        return
    t = time.strftime("%F %T")
    send_async("ok", title, lambda: "用户 %s 从 %s（%s）登录 %s，时间 %s" % (user or "-", ip, geo(ip), via, t))


RE_SSH_FAIL = re.compile(r"sshd\[\d+\]: Failed \S+ for (?:invalid user )?(\S*) from (\S+) port")
RE_SSH_OK = re.compile(r"sshd\[\d+\]: Accepted \S+ for (\S+) from (\S+) port")
RE_CONN_FAIL = [
    re.compile(r"User \[(.*?)\] from \[(.*?)\] failed to (?:log|sign) in (?:to \[.*?\] )?via \[(.*?)\]"),
    re.compile(r"User \[(.*?)\] failed to log in from \[(.*?)\] via \[(.*?)\]"),
]
RE_CONN_OK = [
    re.compile(r"User \[(.*?)\] from \[(.*?)\] logged in successfully via \[(.*?)\]"),
    re.compile(r"User \[(.*?)\] from \[(.*?)\] signed in to \[(.*?)\] successfully"),
]


RE_USER = re.compile(r"User \[(.*?)\]", re.I)
RE_VIA = re.compile(r"via \[(.*?)\]", re.I)
RE_TO = re.compile(r"(?:sign(?:ed)? in|log(?:ged)? in) to \[(.*?)\]", re.I)
RE_FROM = re.compile(r"from \[(.*?)\]", re.I)
GENERIC_VIA = ("PASSWORD", "OTP", "2FA", "PASSKEY", "SSO", "")


def handle_conn_text(text, skip_ssh=False, ip_hint="", user_hint="", via_hint=""):
    """解析 DSM 连接日志。先按已知句式匹配，再按关键字兜底，兼容不同 DSM 版本的写法。"""
    low = text.lower()
    if not (("log" in low or "sign" in low) and ("in" in low)):
        return
    ok = "success" in low
    fail = (not ok) and ("fail" in low or "denied" in low or "incorrect" in low)
    if not ok and not fail:
        return
    m = RE_USER.search(text)
    user = (m.group(1) if m else "") or user_hint
    m = RE_FROM.search(text)
    ip = m.group(1) if m and valid_ip(m.group(1)) else ip_hint
    via = ""
    m = RE_VIA.search(text)
    if m:
        via = m.group(1)
    if via.upper() in GENERIC_VIA:
        m = RE_TO.search(text)
        via = (m.group(1) if m else "") or via_hint or via or "DSM"
    if skip_ssh and via.upper() in ("SSH", "SFTP"):
        return
    if not ip:
        return
    (on_ok if ok else on_fail)(ip, user, via)


def handle_auth_line(line):
    m = RE_SSH_FAIL.search(line)
    if m:
        on_fail(m.group(2), m.group(1), "SSH")
        return
    m = RE_SSH_OK.search(line)
    if m:
        on_ok(m.group(2), m.group(1), "SSH")


def tail_file(path, handler):
    f, ino, pos = None, None, 0
    while not STOP.is_set():
        try:
            st = os.stat(path)
            if f is None or st.st_ino != ino or st.st_size < pos:
                if f:
                    f.close()
                f = open(path, encoding="utf-8", errors="replace")
                if ino is None:
                    f.seek(0, 2)
                ino = st.st_ino
                pos = f.tell()
            line = f.readline()
            if line:
                pos = f.tell()
                try:
                    handler(line)
                except Exception as e:
                    log("处理日志出错:", e)
                continue
            pos = f.tell()
        except FileNotFoundError:
            pass
        except Exception as e:
            log("读取", path, "出错:", e)
        STOP.wait(1)


SNAP_SIG = None


def open_conndb():
    """套件以 package 用户运行，写不了 .SYNOCONNDB-shm，只读打开时看不到还在 WAL 里的新记录。
    所以把库和 WAL 复制到自己的目录再打开（只在文件变化时复制）。"""
    global SNAP_SIG
    wal = CONNDB + "-wal"
    sig = []
    for f in (CONNDB, wal):
        try:
            st = os.stat(f)
            sig.append((st.st_ino, st.st_size, st.st_mtime))
        except FileNotFoundError:
            sig.append(None)
    snap = os.path.join(VAR, "conndb.snap")
    if sig != SNAP_SIG or not os.path.exists(snap):
        for suf in ("", "-wal", "-shm"):
            try:
                os.remove(snap + suf)
            except FileNotFoundError:
                pass
        shutil.copyfile(CONNDB, snap)
        if os.path.exists(wal):
            shutil.copyfile(wal, snap + "-wal")
        SNAP_SIG = sig
    elif getattr(open_conndb, "seen", None) == sig:
        return None
    open_conndb.seen = sig
    return sqlite3.connect(snap, timeout=5)


def poll_conndb(skip_ssh):
    last = None
    errs = 0
    while not STOP.is_set():
        try:
            con = open_conndb()
            if con is None:
                STOP.wait(3)
                continue
            try:
                tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
                tbl = "logs" if "logs" in tables else (tables[0] if tables else None)
                if tbl:
                    top = con.execute("select max(rowid) from %s" % tbl).fetchone()[0] or 0
                    if last is None or top < last:
                        if last is not None:
                            log("连接日志库已重建，重新定位")
                        last = top
                    rows = con.execute("select rowid, * from %s where rowid > ? order by rowid limit 500" % tbl,
                                       (last,)).fetchall()
                    for r in rows:
                        last = r[0]
                        vals = [str(x) for x in r[1:] if x is not None]
                        text = max(vals, key=lambda v: ("User [" in v, len(v))) if vals else ""
                        ip_hint = next((v for v in vals if v != text and valid_ip(v)), "")
                        via_hint = next((v for v in vals if v.upper() in ("SSH", "SFTP", "DSM", "HTTP/HTTPS",
                                                                           "QUICKCONNECT", "WEB")), "")
                        try:
                            handle_conn_text(text, skip_ssh, ip_hint, "", via_hint)
                        except Exception as e:
                            log("处理连接日志出错:", e)
                errs = 0
            finally:
                con.close()
        except Exception as e:
            errs += 1
            if errs in (1, 20) or errs % 600 == 0:
                log("读取连接日志库出错:", e)
        STOP.wait(3)


# ---------------- 每日简报 ----------------
def sysinfo():
    out = []
    try:
        up = float(open("/proc/uptime").read().split()[0])
        out.append("运行 %d 天 %d 小时" % (up // 86400, up % 86400 // 3600))
    except Exception:
        pass
    try:
        out.append("负载 " + " ".join(open("/proc/loadavg").read().split()[:3]))
    except Exception:
        pass
    try:
        mem = {}
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1)
            mem[k] = int(v.split()[0])
        used = (mem["MemTotal"] - mem.get("MemAvailable", mem.get("MemFree", 0))) * 100 // mem["MemTotal"]
        out.append("内存 %d%%" % used)
    except Exception:
        pass
    for vol in sorted(p for p in os.listdir("/") if p.startswith("volume")):
        try:
            s = os.statvfs("/" + vol)
            tot = s.f_blocks * s.f_frsize
            if tot:
                out.append("%s %d%%" % (vol, (tot - s.f_bavail * s.f_frsize) * 100 // tot))
        except Exception:
            pass
    return "，".join(out)


def build_report():
    now = time.time()
    fails, oks, bans_n = {}, [], 0
    for line in read_lines(EVENTS):
        p = line.split("\t")
        if len(p) < 5:
            continue
        try:
            ts = int(p[0])
        except ValueError:
            continue
        if now - ts > 86400:
            continue
        if p[1] == "fail":
            fails[p[2]] = fails.get(p[2], 0) + 1
        elif p[1] == "ok" and p[2] not in ("127.0.0.1", "::1"):
            oks.append(p)
        elif p[1] == "ban":
            bans_n += 1
    total = sum(fails.values())
    body = "过去 24 小时：失败登录 %d 次（%d 个 IP），成功登录 %d 次，新封禁 %d 个。" % (total, len(fails), len(oks), bans_n)
    if fails:
        body += "\n失败最多："
        for i, (ip, n) in enumerate(sorted(fails.items(), key=lambda x: -x[1])[:3], 1):
            body += "\n  %d. %s（%s）%d 次" % (i, ip, geo(ip), n)
    if oks:
        p = oks[-1]
        body += "\n最近登录：%s@%s（%s）%s %s" % (p[3], p[2], geo(p[2]), p[4],
                                            time.strftime("%m-%d %H:%M", time.localtime(int(p[0]))))
    body += "\n当前封禁 %d 个 IP。" % len(get_bans())
    si = sysinfo()
    if si:
        body += "\n系统：" + si
    return "📊 %s 每日安全简报" % hostname(), body


def report_loop():
    done = None
    while not STOP.is_set():
        t = time.localtime()
        key = time.strftime("%F")
        if CFG.get("report_enabled", True) and t.tm_hour == int(CFG.get("report_hour", 9)) \
                and t.tm_min == int(CFG.get("report_minute", 0)) and done != key:
            done = key
            title, body = build_report()
            send("report", title, body)
        STOP.wait(20)


def housekeeping():
    while not STOP.is_set():
        try:
            with LOCK:
                b = get_bans()
                fw_ensure()
                fw_sync(b)
        except Exception as e:
            log("维护防火墙出错:", e)
        STOP.wait(30)


# ---------------- 网页设置 ----------------


AUTH_CACHE = {}
AUTHCGI = "/usr/syno/synoman/webman/modules/authenticate.cgi"


def dsm_session_user(cookie, token, remote, host):
    """用 DSM 自带 authenticate.cgi 校验当前浏览器的 DSM 登录态，要求管理员。"""
    if not cookie:
        return None
    key = (cookie, token, remote)
    now = time.time()
    hit = AUTH_CACHE.get(key)
    if hit and now - hit[1] < 60:
        return hit[0]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HTTP_COOKIE": cookie, "REMOTE_ADDR": remote,
           "HTTP_X_SYNO_TOKEN": token, "QUERY_STRING": "SynoToken=" + urllib.parse.quote(token),
           "REQUEST_METHOD": "GET", "SERVER_NAME": host.split(":")[0], "HTTP_HOST": host,
           "GATEWAY_INTERFACE": "CGI/1.1", "SCRIPT_NAME": "/webman/3rdparty/NasGuard/index.cgi"}
    user = None
    try:
        r = subprocess.run([AUTHCGI], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        lines = [l.strip() for l in r.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
        cand = lines[-1] if lines else ""
        if re.match(r"^[\w.@\\\- ]{1,64}$", cand) and ":" not in cand:
            user = cand if is_admin(cand) else None
            if not user:
                log("DSM 账户", cand, "不是管理员，拒绝访问")
        else:
            log("DSM 会话校验未通过：token=%s cookie=%s remote=%s 输出=%s" % (
                "有" if token else "无", "有" if cookie else "无", remote, " | ".join(lines)[:200] or "空"))
    except Exception as e:
        log("调用 authenticate.cgi 出错:", e)
    if len(AUTH_CACHE) > 200:
        AUTH_CACHE.clear()
    AUTH_CACHE[key] = (user, now)
    return user


def is_admin(user):
    try:
        for line in open("/etc/group", encoding="utf-8"):
            p = line.strip().split(":")
            if p[0] == "administrators" and len(p) > 3 and user in p[3].split(","):
                return True
    except Exception:
        pass
    return user == "admin"


def config_public():
    c = dict(CFG)
    return c


INT_KEYS = {"threshold", "window", "cooldown", "ok_merge", "ban_time", "report_hour", "report_minute"}
BOOL_KEYS = {k for k, v in DEFAULTS.items() if isinstance(v, bool)}


def save_config(data):
    c = cfg()
    for k in DEFAULTS:
        if k not in data:
            continue
        v = data[k]
        if k in INT_KEYS:
            try:
                v = max(0, int(v))
            except Exception:
                continue
        elif k in BOOL_KEYS:
            v = bool(v) and v not in ("0", "false", "off")
        else:
            v = str(v).strip()
        c[k] = v
    c["threshold"] = max(1, c["threshold"])
    c["window"] = max(1, c["window"])
    c["report_hour"] = min(23, c["report_hour"])
    c["report_minute"] = min(59, c["report_minute"])
    save_json(CONF, c)
    reload_cfg()


STATS_CACHE = {}


def fw_ok():
    try:
        return ipt(False, "-n", "-L", CHAIN) == 0
    except Exception:
        return False


def stats():
    """今日与近 7 天的统计。"""
    now = time.time()
    lt = time.localtime(now)
    today0 = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
    days = [today0 - 86400 * i for i in range(6, -1, -1)]
    daily = [{"day": time.strftime("%m-%d", time.localtime(d)), "fail": 0, "ok": 0, "ban": 0} for d in days]
    hourly = [{"h": h, "fail": 0, "ok": 0} for h in range(24)]
    t = {"ok": 0, "fail": 0, "ban": 0, "brute": set(), "fail_ips": {}, "ok_users": set(), "via": {}}
    for line in read_lines(EVENTS):
        p = line.split("\t")
        if len(p) < 5:
            continue
        try:
            ts = int(p[0])
        except ValueError:
            continue
        if ts < days[0]:
            continue
        kind, ip = p[1], p[2]
        if kind == "ok" and ip in ("127.0.0.1", "::1"):
            continue
        di = min(6, int((ts - days[0]) // 86400))
        if kind in ("fail", "ok", "ban"):
            daily[di][kind] += 1
        if ts < today0:
            continue
        h = time.localtime(ts).tm_hour
        if kind in ("fail", "ok"):
            hourly[h][kind] += 1
        if kind == "ok":
            t["ok"] += 1
            t["ok_users"].add(p[3])
        elif kind == "fail":
            t["fail"] += 1
            t["fail_ips"][ip] = t["fail_ips"].get(ip, 0) + 1
            v = p[4] or "其他"
            t["via"][v] = t["via"].get(v, 0) + 1
        elif kind == "ban":
            t["ban"] += 1
        elif kind == "brute":
            t["brute"].add(ip)
    top = sorted(t["fail_ips"].items(), key=lambda x: -x[1])[:5]
    return {
        "today": {"ok": t["ok"], "fail": t["fail"], "fail_ips": len(t["fail_ips"]), "brute": len(t["brute"]),
                  "ban": t["ban"], "users": len(t["ok_users"])},
        "hourly": hourly, "daily": daily,
        "via": sorted(([k, v] for k, v in t["via"].items()), key=lambda x: -x[1]),
        "top": [{"ip": ip, "n": n, "loc": geo(ip), "banned": ip in get_bans()} for ip, n in top],
    }


def status_data():
    bans = get_bans()
    now = time.time()
    bl = []
    for ip, exp in sorted(bans.items(), key=lambda x: x[1] or 9e18):
        bl.append({"ip": ip, "left": "永久" if not exp else fmt_min(max(1, int((exp - now) // 60))), "loc": geo(ip)})
    ev = []
    for line in reversed(read_lines(EVENTS, 100)):
        p = line.split("\t")
        if len(p) >= 5:
            ev.append({"time": time.strftime("%m-%d %H:%M:%S", time.localtime(int(p[0]))), "kind": p[1],
                       "ip": p[2], "user": p[3], "via": p[4]})
    pu = []
    for line in reversed(read_lines(PUSHES, 30)):
        p = line.split("\t")
        if len(p) >= 5:
            pu.append({"time": p[0], "kind": p[1], "st": p[2], "title": p[3], "body": p[4]})
    src = []
    if os.path.exists(AUTHLOG):
        src.append("SSH 日志")
    if os.path.exists(CONNDB):
        src.append("DSM 连接日志")
    elif os.path.exists(MESSAGES):
        src.append("系统日志")
    run = {"running": True, "pid": os.getpid(), "since": time.strftime("%m-%d %H:%M", time.localtime(STARTED)),
           "uptime": fmt_min(max(1, int((now - STARTED) // 60))), "enabled": bool(CFG.get("enabled", True)),
           "ban_enabled": bool(CFG.get("ban_enabled", True)), "firewall": fw_ok(),
           "rule": "%s 分钟内失败 %s 次封禁 %s" % (CFG.get("window", 10), CFG.get("threshold", 5),
                                            "永久" if not int(CFG.get("ban_time", 0) or 0) else fmt_min(int(CFG.get("ban_time")))),
           "report": ("%02d:%02d" % (int(CFG.get("report_hour", 9)), int(CFG.get("report_minute", 0))))
           if CFG.get("report_enabled", True) else "关闭"}
    return {"version": VERSION, "host": hostname(), "run": run, "stats": stats(), "bans": bl,
            "events": ev, "pushes": pu, "sources": src}


class Handler(BaseHTTPRequestHandler):
    server_version = "NasGuard"

    def log_message(self, *a):
        pass

    def address_string(self):
        return "unix"

    def client_ip(self):
        ip = self.headers.get("X-NG-Remote", "")
        return ip[7:] if ip.startswith("::ffff:") else ip

    def user(self):
        return dsm_session_user(self.headers.get("X-NG-Cookie", ""), self.headers.get("X-NG-Token", ""),
                                self.headers.get("X-NG-Remote", ""), self.headers.get("X-NG-Host", ""))

    def send_json(self, obj, code=200, extra=None):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/me":
            u = self.user()
            return self.send_json({"user": u, "version": VERSION})
        if not self.user():
            return self.send_json({"error": "login"}, 401)
        if path == "/api/status":
            return self.send_json(status_data())
        if path == "/api/config":
            return self.send_json(config_public())
        if path == "/api/update":
            return self.send_json(update_info())
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        d = self.body()
        ip = self.client_ip()
        if not self.user():
            return self.send_json({"error": "login"}, 401)
        if path == "/api/config":
            save_config(d)
            return self.send_json({"ok": True})
        if path == "/api/updcheck":
            info = check_update()
            return self.send_json({"ok": not info.get("error"), "info": update_info()})
        if path == "/api/upgrade":
            if UPD_STATE["state"] in ("running", "installing"):
                return self.send_json({"ok": True, "msg": "更新正在进行"})
            threading.Thread(target=do_upgrade, daemon=True).start()
            return self.send_json({"ok": True, "msg": "已开始更新"})
        if path == "/api/test":
            ok, msg = send("test", "🔔 %s NasGuard 测试推送" % hostname(), "推送通道正常，时间 %s" % time.strftime("%F %T"))
            return self.send_json({"ok": ok, "msg": msg})
        if path == "/api/report":
            title, body = build_report()
            ok, msg = send("report", title, body)
            return self.send_json({"ok": ok, "msg": msg})
        if path == "/api/ban":
            t = str(d.get("ip", "")).strip()
            if not valid_ip(t):
                return self.send_json({"ok": False, "msg": "IP 格式不对"})
            if is_lan(t) or t == ip:
                return self.send_json({"ok": False, "msg": "不能封禁内网或你当前的 IP"})
            ban(t, int(d.get("minutes", CFG.get("ban_time", 1440)) or 0), "manual")
            return self.send_json({"ok": True})
        if path == "/api/unban":
            unban(str(d.get("ip", "")))
            return self.send_json({"ok": True})
        self.send_json({"error": "not found"}, 404)


class Server(ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def web_loop():
    """DSM 窗口经 index.cgi 通过本地 Unix 套接字访问，不占用任何网络端口。"""
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    for f in ("web_port",):
        try:
            os.unlink(VAR + "/" + f)
        except Exception:
            pass
    srv = Server(SOCK, Handler)
    os.chmod(SOCK, 0o666)
    try:
        os.chmod(VAR, 0o755)
    except Exception:
        pass
    log("内部服务就绪（Unix 套接字，无网络端口）")
    srv.serve_forever()



# ---------------- 在线更新 ----------------
UPD = VAR + "/update"
UPD_STATE = {"state": "idle", "msg": ""}
MIRRORS = ["-", "https://ghfast.top/", "https://gh-proxy.com/"]


def mirrors():
    m = CFG.get("update_mirror", "auto")
    first = {"direct": "-", "ghfast": "https://ghfast.top/", "ghproxy": "https://gh-proxy.com/"}.get(m)
    if not first:
        return list(MIRRORS)
    return [first] + [x for x in MIRRORS if x != first]


def pre(m):
    return "" if m == "-" else m


def vtuple(v):
    out = []
    for x in re.split(r"[.\-]", str(v).lstrip("v")):
        try:
            out.append(int(x))
        except ValueError:
            out.append(0)
    return tuple(out[:3] + [0] * (3 - len(out[:3])))


def fetch(url, timeout=12, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": "NasGuard/" + VERSION,
                                               "Accept": "application/vnd.github+json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        b = r.read()
    return b if raw else json.loads(b.decode("utf-8"))


def upd_log(*a):
    os.makedirs(UPD, exist_ok=True)
    line = "[%s] %s" % (time.strftime("%T"), " ".join(str(x) for x in a))
    with open(UPD + "/update.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")
    log(*a)


def check_update():
    """返回 dict：latest/date/notes/spk/src/checked，失败时 error。"""
    info = None
    try:
        j = fetch("https://api.github.com/repos/%s/releases/latest" % REPO)
        if j.get("tag_name"):
            spk = ""
            for a in j.get("assets") or []:
                if a.get("name", "").endswith(".spk"):
                    spk = a["name"]
                    break
            info = {"latest": j["tag_name"].lstrip("v"), "date": (j.get("published_at") or "")[:10],
                    "notes": (j.get("body") or "").replace("\r", ""), "spk": spk, "src": "GitHub"}
    except Exception as e:
        log("GitHub API 检查更新失败:", e)
    if not info:
        urls = ["https://cdn.jsdelivr.net/gh/%s@main/version.json" % REPO,
                "https://fastly.jsdelivr.net/gh/%s@main/version.json" % REPO] + \
               [pre(m) + "https://raw.githubusercontent.com/%s/main/version.json" % REPO for m in mirrors()]
        for u in urls:
            try:
                j = fetch(u)
                if j.get("version"):
                    info = {"latest": str(j["version"]), "date": j.get("date", ""), "notes": j.get("notes", ""),
                            "spk": j.get("spk", ""), "src": urllib.parse.urlsplit(u).netloc}
                    break
            except Exception:
                continue
    if not info:
        return {"error": "GitHub 和所有镜像都连不上", "checked": time.strftime("%F %T")}
    if not info["spk"]:
        info["spk"] = "NasGuard-%s-0001.spk" % info["latest"]
    info["checked"] = time.strftime("%F %T")
    info["newer"] = vtuple(info["latest"]) > vtuple(VERSION)
    os.makedirs(UPD, exist_ok=True)
    save_json(UPD + "/info.json", info)
    return info


def update_info():
    info = load_json(UPD + "/info.json", {})
    if info:
        info["newer"] = vtuple(info.get("latest", "0")) > vtuple(VERSION)
    st = dict(UPD_STATE)
    return {"current": VERSION, "repo": REPO, "info": info, "state": st["state"], "msg": st["msg"],
            "log": read_lines(UPD + "/update.log", 60)}


def do_upgrade():
    os.makedirs(UPD, exist_ok=True)
    open(UPD + "/update.log", "w").close()
    UPD_STATE.update(state="running", msg="检查最新版本…")
    upd_log("检查最新版本…")
    info = check_update()
    if info.get("error"):
        UPD_STATE.update(state="fail", msg="检查失败")
        return upd_log("❌ 检查失败：" + info["error"])
    if not info.get("newer"):
        UPD_STATE.update(state="done", msg="已是最新")
        return upd_log("✅ 已是最新版本 v" + VERSION)
    ver, spk = info["latest"], info["spk"]
    f = UPD + "/new.spk"
    ok = False
    for m in mirrors():
        url = pre(m) + "https://github.com/%s/releases/download/v%s/%s" % (REPO, ver, spk)
        upd_log("下载 v%s（%s）" % (ver, "直连 GitHub" if m == "-" else "经 " + m))
        try:
            b = fetch(url, timeout=120, raw=True)
            with open(f, "wb") as fh:
                fh.write(b)
            import tarfile
            with tarfile.open(f) as t:
                names = t.getnames()
            if "INFO" in names and "package.tgz" in names:
                ok = True
                break
            upd_log("  文件不对，换下一条线路")
        except Exception as e:
            upd_log("  失败：", e)
    if not ok:
        UPD_STATE.update(state="fail", msg="下载失败")
        return upd_log("❌ 所有线路下载失败，可到 GitHub Release 手动下载 spk 在套件中心安装")
    upd_log("下载完成 %d 字节，开始安装（套件会自动重启，窗口稍后刷新即可）" % os.path.getsize(f))
    save_json(UPD + "/pending.json", {"ver": ver, "notes": info.get("notes", "")[:600]})
    sh = UPD + "/upgrade.sh"
    with open(sh, "w") as fh:
        fh.write("#!/bin/sh\n"
                 "# 先把自己移出套件的 cgroup，否则停止套件时安装进程会被一起结束\n"
                 "for f in /sys/fs/cgroup/*/cgroup.procs /sys/fs/cgroup/cgroup.procs; do\n"
                 "  [ -w \"$f\" ] && echo $$ > \"$f\" 2>/dev/null\n"
                 "done\n"
                 "trap '' HUP TERM\n"
                 "sleep 2\nL=%s/update.log\n"
                 "echo \"[$(date +%%T)] synopkg install …\" >> $L\n"
                 "/usr/syno/bin/synopkg install %s >> $L 2>&1\n"
                 "echo \"[$(date +%%T)] 安装命令结束（返回 $?）\" >> $L\n"
                 "/usr/syno/bin/synopkg start NasGuard >> $L 2>&1\n" % (UPD, f))
    os.chmod(sh, 0o755)
    cmd = ["/bin/sh", sh]
    if has_cmd("setsid"):
        cmd = ["setsid"] + cmd
    if has_cmd("nohup"):
        cmd = ["nohup"] + cmd
    upd_log("启动安装进程（已脱离套件）")
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                     preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN))
    UPD_STATE.update(state="installing", msg="正在安装 v" + ver)


def after_start_update():
    """新版本启动后：确认升级结果并推送一次。"""
    p = load_json(UPD + "/pending.json", {})
    if not p:
        return
    try:
        os.unlink(UPD + "/pending.json")
    except Exception:
        pass
    if p.get("ver") == VERSION:
        upd_log("✅ 已更新到 v" + VERSION)
        UPD_STATE.update(state="done", msg="已更新到 v" + VERSION)
        save_json(UPD + "/notified.json", {"ver": VERSION})
        send_async("update", "✅ %s NasGuard 已更新到 v%s" % (hostname(), VERSION), lambda: p.get("notes") or "更新完成")
    else:
        upd_log("❌ 安装未成功，当前仍为 v" + VERSION)
        UPD_STATE.update(state="fail", msg="安装失败")


def update_loop():
    STOP.wait(120)
    while not STOP.is_set():
        try:
            update_check_notify()
        except Exception as e:
            log("定时检查更新出错:", e)
        STOP.wait(12 * 3600)


def update_check_notify():
    if True:
        if CFG.get("notify_update", True):
            info = check_update()
            if info.get("newer") and load_json(UPD + "/notified.json", {}).get("ver") != info["latest"]:
                ok, _ = send("update", "🆕 %s NasGuard v%s 可更新" % (hostname(), info["latest"]),
                             "当前 v%s，最新 v%s（%s）\n%s\n\n打开 DSM 里的 NasGuard →「在线更新」一键升级" % (
                                 VERSION, info["latest"], info.get("date", ""), info.get("notes", "")[:500]))
                if ok:
                    save_json(UPD + "/notified.json", {"ver": info["latest"]})


# ---------------- 入口 ----------------
def daemon():
    os.makedirs(VAR, exist_ok=True)
    if not os.path.exists(CONF):
        save_json(CONF, DEFAULTS)
    reload_cfg()
    log("NasGuard", VERSION, "启动")

    def stop(*_):
        STOP.set()
        log("收到停止信号")
        os._exit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    fw_ensure()
    fw_sync(get_bans())
    after_start_update()
    threads = [threading.Thread(target=housekeeping, daemon=True),
               threading.Thread(target=report_loop, daemon=True),
               threading.Thread(target=web_loop, daemon=True),
               threading.Thread(target=update_loop, daemon=True)]
    use_auth = os.path.exists(AUTHLOG)
    if use_auth:
        threads.append(threading.Thread(target=tail_file, args=(AUTHLOG, handle_auth_line), daemon=True))
    if os.path.exists(CONNDB):
        threads.append(threading.Thread(target=poll_conndb, args=(False,), daemon=True))
    else:
        threads.append(threading.Thread(target=tail_file, args=(MESSAGES, lambda l: handle_conn_text(l, False)),
                                        daemon=True))
    for t in threads:
        t.start()
    last_mtime = 0
    while not STOP.is_set():
        try:
            m = os.path.getmtime(CONF)
            if m != last_mtime:
                last_mtime = m
                reload_cfg()
        except Exception:
            pass
        STOP.wait(5)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "daemon"
    reload_cfg()
    if cmd == "daemon":
        daemon()
    elif cmd == "fwclean":
        fw_clean()
    elif cmd == "test":
        print(send("test", "🔔 %s NasGuard 测试推送" % hostname(), "推送通道正常"))
    elif cmd == "report":
        print(send("report", *build_report()))
    elif cmd == "unban":
        unban(sys.argv[2])
    elif cmd == "bans":
        for ip, exp in get_bans().items():
            print(ip, "永久" if not exp else time.strftime("%F %T", time.localtime(exp)))
    elif cmd == "selftest":
        for line in sys.stdin:
            handle_auth_line(line)
            handle_conn_text(line, False)
    else:
        print("用法: guard.py daemon|fwclean|test|report|bans|unban IP")


if __name__ == "__main__":
    main()
