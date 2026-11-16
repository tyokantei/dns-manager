# coding=utf-8
"""
DNS Manager —— 个人阿里云 DNS 管理面板
- 后端：Python 标准库（无第三方依赖），DNS 操作复用 dns_core.aliDns（源自 demo.py）
- 前端：web/index.html 单文件
- HTTPS：自签名证书（cert.pem / key.pem），缺失时启动自动用 openssl 生成
- 数据：data/auth.json（面板密码，PBKDF2）、data/store.json（密钥档案 + 模板），权限 600
- 设计：不写死任何域名；多密钥档案（profile），每个档案管辖若干主域名
用法：python3 app.py [--port 8550]
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import socketserver
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler
from urllib import request as urlrequest
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dns_core import aliDns

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
STORE_FILE = os.path.join(DATA_DIR, "store.json")
CERT_FILE = os.path.join(BASE, "cert.pem")
KEY_FILE = os.path.join(BASE, "key.pem")
WEB_FILE = os.path.join(BASE, "web", "index.html")

SESSION_TTL = 12 * 3600
PBKDF2_ROUNDS = 120000

DEFAULT_TEMPLATES = [
    {"name": "Jetson设备", "domain": "", "rr": "jetson1", "type": "A", "value": "", "line": "default", "ttl": 600},
    {"name": "家庭NAS", "domain": "", "rr": "nas", "type": "A", "value": "", "line": "default", "ttl": 600},
    {"name": "影音服务", "domain": "", "rr": "media", "type": "A", "value": "", "line": "default", "ttl": 600},
    {"name": "远程管理", "domain": "", "rr": "remote", "type": "A", "value": "", "line": "default", "ttl": 600},
    {"name": "域名别名", "domain": "", "rr": "tvbox", "type": "CNAME", "value": "", "line": "default", "ttl": 600},
]


def _write_private(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_auth():
    try:
        with open(AUTH_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_auth(obj):
    _write_private(AUTH_FILE, obj)


def load_store():
    try:
        with open(STORE_FILE, encoding="utf-8") as f:
            s = json.load(f)
        s.setdefault("profiles", [])
        s.setdefault("templates", [])
        s.setdefault("notes", {})
        s.setdefault("locks", {})
        s.setdefault("services", [])
        return s
    except Exception:
        return {"profiles": [], "templates": list(DEFAULT_TEMPLATES), "notes": {}, "services": []}


def save_store(s):
    _write_private(STORE_FILE, s)


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex(), dk.hex()


def make_token(auth):
    exp = int(time.time()) + SESSION_TTL
    sig = hmac.new(bytes.fromhex(auth["secret"]), str(exp).encode(), hashlib.sha256).hexdigest()
    return "%d.%s" % (exp, sig)


def check_token(auth, token):
    if not auth or not token or "." not in token:
        return False
    exp_s, sig = token.rsplit(".", 1)
    try:
        exp = int(exp_s)
    except ValueError:
        return False
    if exp < int(time.time()):
        return False
    want = hmac.new(bytes.fromhex(auth["secret"]), str(exp).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


def profile_for_domain(store, domain):
    for p in store["profiles"]:
        if domain in (p.get("domains") or []):
            return p
    return None


def dns_client(profile):
    return aliDns(profile["key_id"], profile["key_secret"])


def public_ip():
    for url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"):
        try:
            with urlrequest.urlopen(url, timeout=5) as r:
                ip = r.read().decode("utf-8", "ignore").strip()
            if ip and len(ip) <= 45 and all(c in "0123456789abcdefABCDEF:." for c in ip):
                return ip
        except Exception:
            continue
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DnsManager/1.0"

    # ---------- plumbing ----------
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def _authed(self):
        auth = load_auth()
        if not auth:
            return False
        cookie = self.headers.get("Cookie") or ""
        token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("dnsmgr="):
                token = part[len("dnsmgr="):]
        return check_token(auth, token)

    def _need_auth(self):
        if self._authed():
            return True
        self._send(401, {"ok": False, "msg": "未登录"})
        return False

    # ---------- GET ----------
    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path in ("/", "/index.html"):
            try:
                with open(WEB_FILE, "rb") as f:
                    body = f.read()
            except Exception:
                return self._send(500, "web/index.html missing", "text/plain; charset=utf-8")
            return self._send(200, body, "text/html; charset=utf-8")
        if path == "/api/me":
            auth = load_auth()
            return self._send(200, {"ok": True, "setup": auth is None, "authed": self._authed()})
        if not path.startswith("/api/"):
            return self._send(404, {"ok": False, "msg": "not found"})
        if not self._need_auth():
            return
        store = load_store()
        if path == "/api/profiles":
            out = []
            for p in store["profiles"]:
                kid = p.get("key_id", "")
                out.append({
                    "name": p["name"],
                    "key_id_masked": (kid[:6] + "****" + kid[-2:]) if len(kid) > 8 else "****",
                    "domains": p.get("domains") or [],
                })
            return self._send(200, {"ok": True, "profiles": out})
        if path == "/api/templates":
            return self._send(200, {"ok": True, "templates": store["templates"]})
        if path == "/api/notes":
            domain = (qs.get("domain") or [""])[0]
            notes = {k: v for k, v in (store.get("notes") or {}).items()
                     if k.startswith(domain + "|")}
            return self._send(200, {"ok": True, "notes": notes})
        if path == "/api/locks":
            domain = (qs.get("domain") or [""])[0]
            locks = {k: v for k, v in (store.get("locks") or {}).items()
                     if k.startswith(domain + "|")}
            return self._send(200, {"ok": True, "locks": locks})
        if path == "/api/services":
            return self._send(200, {"ok": True, "services": store.get("services") or []})
        if path == "/api/sync-status":
            domain = (qs.get("domain") or [""])[0]
            prof = profile_for_domain(store, domain)
            if not prof:
                return self._send(200, {"ok": False, "msg": "该域名没有对应的密钥档案"})
            res = dns_client(prof).get_all(domain)
            if res.get("code") == -1:
                return self._send(200, {"ok": False, "msg": res.get("msg", "获取失败")})
            by_rr = {}
            for r in res["records"]:
                by_rr.setdefault(r.get("RR", ""), []).append({
                    "record_id": r.get("RecordId"), "status": r.get("Status", "Enable"),
                    "type": r.get("Type"), "value": r.get("Value")})
            return self._send(200, {"ok": True, "by_rr": by_rr})
        if path == "/api/records":
            domain = (qs.get("domain") or [""])[0]
            prof = profile_for_domain(store, domain)
            if not prof:
                return self._send(200, {"ok": False, "msg": "该域名没有对应的密钥档案，请先在「设置」里添加"})
            res = dns_client(prof).get_all(domain)
            if res.get("code") == -1:
                return self._send(200, {"ok": False, "msg": res.get("msg", "获取失败")})
            return self._send(200, {"ok": True, "records": res["records"], "total": res["total"]})
        if path == "/api/public-ip":
            ip = public_ip()
            if ip:
                return self._send(200, {"ok": True, "ip": ip})
            return self._send(200, {"ok": False, "msg": "获取公网 IP 失败（可在输入框手动填写）"})
        return self._send(404, {"ok": False, "msg": "not found"})

    # ---------- POST ----------
    def do_POST(self):
        path = urlparse(self.path).path
        body = self._json_body()
        if path == "/api/setup":
            if load_auth() is not None:
                return self._send(403, {"ok": False, "msg": "已设置过密码"})
            pw = (body.get("password") or "").strip()
            if len(pw) < 6:
                return self._send(200, {"ok": False, "msg": "密码至少 6 位"})
            salt, dk = hash_password(pw)
            auth = {"salt": salt, "hash": dk, "secret": secrets.token_bytes(32).hex()}
            save_auth(auth)
            tok = make_token(auth)
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": "dnsmgr=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax" % (tok, SESSION_TTL)})
        if path == "/api/login":
            auth = load_auth()
            if not auth:
                return self._send(200, {"ok": False, "msg": "尚未设置面板密码"})
            pw = body.get("password") or ""
            _, dk = hash_password(pw, auth["salt"])
            if not hmac.compare_digest(dk, auth["hash"]):
                return self._send(200, {"ok": False, "msg": "密码不正确"})
            tok = make_token(auth)
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": "dnsmgr=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax" % (tok, SESSION_TTL)})
        if path == "/api/logout":
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": "dnsmgr=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"})
        if not path.startswith("/api/"):
            return self._send(404, {"ok": False, "msg": "not found"})
        if not self._need_auth():
            return
        store = load_store()

        if path == "/api/change-password":
            auth = load_auth()
            _, dk = hash_password(body.get("old") or "", auth["salt"])
            if not hmac.compare_digest(dk, auth["hash"]):
                return self._send(200, {"ok": False, "msg": "旧密码不正确"})
            new = (body.get("new") or "").strip()
            if len(new) < 6:
                return self._send(200, {"ok": False, "msg": "新密码至少 6 位"})
            salt, dk2 = hash_password(new)
            auth["salt"], auth["hash"] = salt, dk2
            save_auth(auth)
            return self._send(200, {"ok": True, "msg": "密码已更新"})

        if path == "/api/profiles/save":
            name = (body.get("name") or "").strip()
            if not name:
                _doms = [d.strip() for d in (body.get("domains") or []) if str(d).strip()]
                name = _doms[0] if _doms else "默认档案"
            domains = [d.strip().lower() for d in (body.get("domains") or []) if str(d).strip()]
            existing = next((p for p in store["profiles"] if p["name"] == name), None)
            kid = (body.get("key_id") or "").strip()
            ksecret = (body.get("key_secret") or "").strip()
            if existing:
                if kid:
                    existing["key_id"] = kid
                if ksecret:
                    existing["key_secret"] = ksecret
                existing["domains"] = domains
            else:
                if not kid or not ksecret:
                    return self._send(200, {"ok": False, "msg": "新档案需要填 AccessKeyId 和 AccessSecret"})
                store["profiles"].append({"name": name, "key_id": kid, "key_secret": ksecret, "domains": domains})
            save_store(store)
            return self._send(200, {"ok": True, "msg": "档案已保存"})

        if path == "/api/profiles/delete":
            name = body.get("name") or ""
            store["profiles"] = [p for p in store["profiles"] if p["name"] != name]
            save_store(store)
            return self._send(200, {"ok": True, "msg": "档案已删除"})

        if path == "/api/templates/save":
            tpl = {
                "name": (body.get("name") or "").strip(),
                "domain": (body.get("domain") or "").strip(),
                "rr": (body.get("rr") or "").strip(),
                "type": (body.get("type") or "A").strip(),
                "value": (body.get("value") or "").strip(),
                "line": (body.get("line") or "default").strip(),
                "ttl": int(body.get("ttl") or 600),
            }
            if not tpl["name"]:
                return self._send(200, {"ok": False, "msg": "模板名不能为空"})
            store["templates"] = [t for t in store["templates"] if t["name"] != tpl["name"]]
            store["templates"].append(tpl)
            save_store(store)
            return self._send(200, {"ok": True, "msg": "模板已保存"})

        if path == "/api/templates/delete":
            name = body.get("name") or ""
            store["templates"] = [t for t in store["templates"] if t["name"] != name]
            save_store(store)
            return self._send(200, {"ok": True, "msg": "模板已删除"})

        if path == "/api/notes/save":
            domain = (body.get("domain") or "").strip()
            rr = (body.get("rr") or "").strip()
            rtype = (body.get("type") or "").strip()
            note = (body.get("note") or "").strip()
            if not domain or not rr or not rtype:
                return self._send(200, {"ok": False, "msg": "缺少记录标识"})
            key = "%s|%s|%s" % (domain, rr, rtype)
            store.setdefault("notes", {})
            if note:
                store["notes"][key] = note
            else:
                store["notes"].pop(key, None)
            save_store(store)
            return self._send(200, {"ok": True, "msg": "用途已保存"})

        if path == "/api/locks/save":
            domain = (body.get("domain") or "").strip()
            rr = (body.get("rr") or "").strip()
            rtype = (body.get("type") or "").strip()
            if not domain or not rr or not rtype:
                return self._send(200, {"ok": False, "msg": "缺少记录标识"})
            key = "%s|%s|%s" % (domain, rr, rtype)
            store.setdefault("locks", {})
            if body.get("locked"):
                store["locks"][key] = True
            else:
                store["locks"].pop(key, None)
            save_store(store)
            return self._send(200, {"ok": True, "msg": "已锁定" if body.get("locked") else "已解锁"})

        if path == "/api/services/save":
            svc = {
                "domain": (body.get("domain") or "").strip(),
                "rr": (body.get("rr") or "").strip(),
                "intro": (body.get("intro") or "").strip(),
                "lan_ip": (body.get("lan_ip") or "").strip(),
                "lan_port": (body.get("lan_port") or "").strip(),
                "type": (body.get("type") or "CNAME").strip(),
                "value": (body.get("value") or "").strip(),
            }
            if not svc["domain"] or not svc["rr"]:
                return self._send(200, {"ok": False, "msg": "主域名和前缀不能为空"})
            if not svc["value"]:
                svc["value"] = "tyokantei.3322.org" if svc["type"] == "CNAME" else svc["lan_ip"]
            key = svc["domain"] + "|" + svc["rr"]
            store["services"] = [s for s in (store.get("services") or [])
                                 if s["domain"] + "|" + s["rr"] != key]
            store["services"].append(svc)
            save_store(store)
            return self._send(200, {"ok": True, "msg": "项目已保存"})

        if path == "/api/services/delete":
            key = (body.get("domain") or "").strip() + "|" + (body.get("rr") or "").strip()
            store["services"] = [s for s in (store.get("services") or [])
                                 if s["domain"] + "|" + s["rr"] != key]
            save_store(store)
            return self._send(200, {"ok": True, "msg": "项目已删除（仅删面板清单，阿里云记录不动）"})

        # ---- 以下都需要目标域名 + 对应档案 ----
        domain = (body.get("domain") or "").strip()
        prof = profile_for_domain(store, domain)
        if not prof:
            return self._send(200, {"ok": False, "msg": "该域名没有对应的密钥档案"})
        dns = dns_client(prof)

        if path == "/api/add":
            rr = (body.get("rr") or "").strip() or "@"
            res = dns.add(RR=rr, DomainName=domain, Type=(body.get("type") or "A").strip(),
                          Value=(body.get("value") or "").strip(),
                          Line=(body.get("line") or "default").strip(),
                          TTL=str(body.get("ttl") or 600))
            if isinstance(res, dict) and res.get("RequestId"):
                return self._send(200, {"ok": True, "msg": "添加成功", "record_id": res.get("RecordId")})
            return self._send(200, {"ok": False, "msg": (res or {}).get("Message") or (res or {}).get("msg") or "添加失败"})

        if path == "/api/batch-add":
            rrs = [r.strip() for r in (body.get("rrs") or []) if str(r).strip()]
            if not rrs:
                return self._send(200, {"ok": False, "msg": "没有要添加的前缀"})
            results = []
            for rr in rrs:
                res = dns.add(RR=rr, DomainName=domain, Type=(body.get("type") or "A").strip(),
                              Value=(body.get("value") or "").strip(),
                              Line=(body.get("line") or "default").strip(),
                              TTL=str(body.get("ttl") or 600))
                ok = isinstance(res, dict) and bool(res.get("RequestId"))
                results.append({"rr": rr, "ok": ok,
                                "msg": "成功" if ok else ((res or {}).get("Message") or (res or {}).get("msg") or "失败")})
            return self._send(200, {"ok": True, "results": results})

        if path == "/api/update":
            rid = (body.get("record_id") or "").strip()
            if not rid:
                return self._send(200, {"ok": False, "msg": "缺少 RecordId"})
            res = dns.update(RecordId=rid, DomainName=domain,
                             New_RR=(body.get("rr") or "").strip() or None,
                             New_Type=(body.get("type") or "").strip() or None,
                             New_Value=(body.get("value") or "").strip() or None,
                             New_Line=(body.get("line") or "").strip() or None,
                             New_TTL=str(body.get("ttl")) if body.get("ttl") else None)
            ok = isinstance(res, dict) and res.get("code") == 0
            return self._send(200, {"ok": ok, "msg": (res or {}).get("msg") or ("更新完成" if ok else "更新失败")})

        if path == "/api/delete":
            rid = (body.get("record_id") or "").strip()
            rr = (body.get("rr") or "").strip()
            rtype = (body.get("type") or "").strip()
            if not rid:
                return self._send(200, {"ok": False, "msg": "缺少 RecordId"})
            lkey = "%s|%s|%s" % (domain, rr, rtype)
            if (store.get("locks") or {}).get(lkey):
                return self._send(200, {"ok": False, "msg": "该记录已锁定，不能删除（先解锁）"})
            if rr.startswith("_acme-challenge"):
                return self._send(200, {"ok": False, "msg": "证书校验记录，受保护，不能删除"})
            allres = dns.get_all(domain)
            if allres.get("code") == 0:
                fq = domain if rr in ("@", "") else rr + "." + domain
                refs = sum(1 for x in allres["records"]
                           if (x.get("Value") or "").rstrip(".").lower() == fq.lower()
                           and x.get("RecordId") != rid)
                if refs:
                    return self._send(200, {"ok": False, "msg": "该记录被 %d 条记录引用，不能删除" % refs})
            res = dns.delete(RR=rr, DomainName=domain, RecordId=rid)
            n = len((res or {}).get("record") or [])
            return self._send(200, {"ok": n > 0, "msg": "已删除" if n else "删除失败"})

        if path == "/api/services/push":
            rr = (body.get("rr") or "").strip()
            svc = next((s for s in (store.get("services") or [])
                        if s["domain"] == domain and s["rr"] == rr), None)
            if not svc:
                return self._send(200, {"ok": False, "msg": "项目不存在"})
            existing = dns.search(DomainName=domain, RR=rr)["DomainRecords"]["Record"]
            if existing:
                return self._send(200, {"ok": True, "msg": "阿里云已有该前缀记录，已同步"})
            res = dns.add(RR=rr, DomainName=domain, Type=svc.get("type") or "CNAME",
                          Value=svc.get("value") or "", Line="default", TTL="600")
            if isinstance(res, dict) and res.get("RequestId"):
                return self._send(200, {"ok": True, "msg": "已推送到阿里云", "record_id": res.get("RecordId")})
            return self._send(200, {"ok": False, "msg": (res or {}).get("Message") or (res or {}).get("msg") or "推送失败"})

        if path == "/api/set-status":
            rid = (body.get("record_id") or "").strip()
            status = (body.get("status") or "").strip()
            if not rid or status not in ("Enable", "Disable"):
                return self._send(200, {"ok": False, "msg": "参数不对"})
            res = dns.update(RecordId=rid, DomainName=domain, New_Status=status)
            ok = isinstance(res, dict) and res.get("code") == 0
            return self._send(200, {"ok": ok,
                                    "msg": ("已停用，阿里云同步生效" if status == "Disable" else "已启用，阿里云同步生效") if ok
                                           else ((res or {}).get("msg") or "操作失败")})

        if path == "/api/ddns-update":
            rr = (body.get("rr") or "").strip()
            value = (body.get("value") or "").strip()
            if not rr or not value:
                return self._send(200, {"ok": False, "msg": "前缀和新值不能为空"})
            ids = dns.getDnsRecordId(DomainName=domain, RR=rr, Type="A").get("RecordIds") or []
            if not ids:
                return self._send(200, {"ok": False, "msg": "没找到该前缀的 A 记录（可先在上方新增）"})
            msgs = []
            ok_all = True
            for rid in ids:
                res = dns.update(RecordId=rid, DomainName=domain, New_Value=value)
                ok = isinstance(res, dict) and res.get("code") == 0
                ok_all = ok_all and ok
                msgs.append((res or {}).get("msg", ""))
            return self._send(200, {"ok": ok_all, "msg": "已更新 %d 条记录。%s" % (len(ids), " ".join(msgs))})

        return self._send(404, {"ok": False, "msg": "not found"})


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def ensure_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", KEY_FILE, "-out", CERT_FILE, "-days", "3650",
           "-subj", "/CN=dns-manager",
           "-addext", "subjectAltName=DNS:localhost,DNS:edge640,IP:127.0.0.1"]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        cmd2 = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", KEY_FILE, "-out", CERT_FILE, "-days", "3650",
                "-subj", "/CN=dns-manager"]
        try:
            subprocess.run(cmd2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False


def main():
    ap = argparse.ArgumentParser(description="DNS Manager 面板")
    ap.add_argument("--port", type=int, default=8550)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except Exception:
        pass
    if not os.path.exists(STORE_FILE):
        save_store(load_store())
    if not ensure_cert():
        print("无法生成自签名证书：请先安装 openssl，或手动放置 cert.pem / key.pem 到程序目录。", file=sys.stderr)
        return 1
    httpd = Server((args.host, args.port), Handler)
    ctx = ssl.SSLContext(getattr(ssl, "PROTOCOL_TLS_SERVER", None) or ssl.PROTOCOL_TLSv1_2)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("DNS Manager 已启动: https://%s:%d （自签名证书，浏览器首次访问点继续即可）" % (args.host, args.port))
    if load_auth() is None:
        print("首次运行：打开页面后先设置面板密码，然后在「设置」里添加阿里云密钥档案。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
