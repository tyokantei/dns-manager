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


def check_password(password):
    """校验面板登录密码（删除等危险操作二次确认用，和登录密码一致）。"""
    auth = load_auth()
    if not auth or not password:
        return False
    try:
        _, dk = hash_password(password, auth["salt"])
        return hmac.compare_digest(dk, auth["hash"])
    except Exception:
        return False


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


NGINX_GEN_CONF = "/etc/nginx/conf.d/dnsmgr.conf"
PANEL_PORT = 8550
DEFAULT_CERT = "/home/snowflyjune/app/certd/data/fullchain.pem"
DEFAULT_KEY = "/home/snowflyjune/app/certd/data/privkey.pem"


def nginx_settings(store):
    ng = store.get("nginx") or {}

    def _int(key, dft):
        try:
            return int(ng.get(key))
        except Exception:
            return dft
    st = {"listen": _int("listen", 400),
          "panel_port": _int("panel_port", 8550),
          "redirect": _int("redirect", 800),
          "self_host": (ng.get("self_host") or "dns.tyokantei.cn").strip(),
          "cert_file": (ng.get("cert_file") or DEFAULT_CERT).strip(),
          "key_file": (ng.get("key_file") or DEFAULT_KEY).strip()}
    # 防呆：面板已迁走（当前端口 != 入口端口）时，面板自身端口就是事实，强制对齐
    if PANEL_PORT != st["listen"]:
        st["panel_port"] = PANEL_PORT
    return st


def nginx_settings_error(st):
    """面板自身设置的合法性检查；返回错误文案，空串表示通过。"""
    if st["self_host"] and "." not in st["self_host"]:
        return "面板自身域名「%s」不是完整域名，应填如 dns.tyokantei.cn（不要填服务前缀）" % st["self_host"]
    return ""


def nginx_routes(store):
    routes, seen = [], set()
    for s in store.get("services") or []:
        ip = (s.get("lan_ip") or "").strip()
        port = (s.get("lan_port") or "").strip()
        if not ip or not port:
            continue
        host = ((s.get("rr") or "").strip() + "." + (s.get("domain") or "").strip()).strip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        routes.append({"host": host, "backend": "%s:%s" % (ip, port),
                       "scheme": "https" if s.get("https") else "http", "src": "服务项目"})
    return routes


def _server_block(host, scheme, backend, st):
    lines = ["server {",
             "    listen %d ssl;" % st["listen"],
             "    server_name %s;" % host,
             "    ssl_certificate %s;" % st["cert_file"],
             "    ssl_certificate_key %s;" % st["key_file"],
             "    ssl_session_timeout 5m;",
             "    ssl_protocols TLSv1.2 TLSv1.3;",
             "    location / {",
             "        proxy_set_header HOST $http_host;",
             "        proxy_set_header X-Forwarded-Proto $scheme;",
             "        proxy_set_header X-Real-IP $remote_addr;",
             "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
             "        proxy_set_header Upgrade $http_upgrade;",
             "        proxy_set_header Connection upgrade;",
             "        proxy_pass %s://%s;" % (scheme, backend),
             "    }",
             "}"]
    if st["redirect"]:
        lines += ["server {",
                  "    listen %d;" % st["redirect"],
                  "    server_name %s;" % host,
                  "    return 301 https://$host:%d$request_uri;" % st["listen"],
                  "}"]
    return "\n".join(lines)


def gen_nginx_conf(store):
    st = nginx_settings(store)
    routes = nginx_routes(store)
    hosts = {r["host"] for r in routes}
    blocks = ["# 由 DNS Manager 面板生成，请勿手改；手写的服务请放在其他 .conf 文件里"]
    for r in routes:
        blocks.append(_server_block(r["host"], r["scheme"], r["backend"], st))
    if st["self_host"] and st["self_host"] not in hosts:
        blocks.append(_server_block(st["self_host"], "https",
                                    "127.0.0.1:%d" % st["panel_port"], st))
    return "\n\n".join(blocks) + "\n"


def _run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or ""))
    except Exception as e:
        return -1, str(e)


def nginx_status(store):
    installed = os.path.exists("/usr/sbin/nginx") or _run(["which", "nginx"])[0] == 0
    rc, out = _run(["systemctl", "is-active", "nginx"], timeout=15)
    conf = ""
    try:
        with open(NGINX_GEN_CONF, encoding="utf-8") as f:
            conf = f.read()
    except Exception:
        pass
    included = None
    if installed:
        _, tout = _run(["nginx", "-T"], timeout=20)
        included = "dnsmgr.conf" in tout
    return {"installed": installed, "active": out.strip() == "active",
            "settings": nginx_settings(store), "routes": nginx_routes(store),
            "panel_port": PANEL_PORT, "conf_exists": bool(conf),
            "insync": bool(conf) and conf == gen_nginx_conf(store),
            "included": included}


def _apply_nginx(store):
    """生成 dnsmgr.conf → nginx -t → 重启。返回 (ok, msg, pending)。"""
    if not nginx_status(store)["installed"]:
        return False, "nginx 未安装", False
    err = nginx_settings_error(nginx_settings(store))
    if err:
        return False, err + "，请先改好面板自身设置", False
    conf = gen_nginx_conf(store)
    try:
        if os.path.exists(NGINX_GEN_CONF):
            with open(NGINX_GEN_CONF, encoding="utf-8") as f:
                old = f.read()
            bak = NGINX_GEN_CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")
            with open(bak, "w", encoding="utf-8") as f:
                f.write(old)
        with open(NGINX_GEN_CONF, "w", encoding="utf-8") as f:
            f.write(conf)
    except Exception as e:
        return False, "写配置失败（面板需以 root 运行）：" + str(e), False
    rc, out = _run(["nginx", "-t"], timeout=30)
    if rc != 0:
        return False, "nginx 配置测试未通过：" + out.strip()[-300:], False
    st = nginx_settings(store)
    if PANEL_PORT == st["listen"]:
        return True, "配置已生成并通过测试，但面板正占用入口端口 %d：点「一键切换到 nginx」完成迁移" % st["listen"], True
    _run(["systemctl", "enable", "nginx"], timeout=30)
    rc, out = _run(["systemctl", "restart", "nginx"], timeout=60)
    if rc != 0:
        return False, "nginx 重启失败：" + out.strip()[-300:], False
    return True, "nginx 已按新分流表运行", False


def _install_nginx():
    """apt 安装 nginx 到系统标准位置（/usr/sbin/nginx、/etc/nginx）。返回 (ok, msg)。"""
    _run(["apt-get", "update"], timeout=300)
    _run(["apt-get", "install", "-y", "nginx", "libnginx-mod-stream"], timeout=600)
    if os.path.exists("/usr/sbin/nginx"):
        return True, "nginx 已安装（标准位置 /etc/nginx）"
    return False, "nginx 安装失败"


def _ensure_nginx(store):
    """一键上线前置：没装先自动装。返回 (ok, steps)。"""
    if nginx_status(store)["installed"]:
        return True, []
    ok, m = _install_nginx()
    return ok, [m]


def _fix_include():
    """把 dnsmgr.conf 的 include 行加进 nginx.conf（跟在 web.conf 那行后面）。返回 (ok, msg)。"""
    conf_path = "/etc/nginx/nginx.conf"
    try:
        with open(conf_path, encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        return False, "读 nginx.conf 失败：" + str(e)
    if "dnsmgr.conf" in text:
        return True, "include 已存在，无需修复"
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if "include" in ln and "conf.d/web.conf" in ln:
            indent = ln[:len(ln) - len(ln.lstrip())]
            lines.insert(i + 1, indent + "include /etc/nginx/conf.d/dnsmgr.conf;")
            break
    else:
        return False, "nginx.conf 里没找到 web.conf 的 include 行，无法自动修复"
    try:
        bak = conf_path + ".bak-" + time.strftime("%Y%m%d%H%M%S")
        with open(bak, "w", encoding="utf-8") as f:
            f.write(text)
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except Exception as e:
        return False, "写 nginx.conf 失败：" + str(e)
    rc, out = _run(["nginx", "-t"], timeout=30)
    if rc != 0:
        try:
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass
        return False, "改完配置测试未通过，已回滚：" + out.strip()[-200:]
    rc, out = _run(["systemctl", "restart", "nginx"], timeout=60)
    if rc != 0:
        return False, "include 已加好，但 nginx 重启失败：" + out.strip()[-200:]
    return True, "已自动补上 include 并重启 nginx"


def _push_service(dns, domain, svc):
    """把一条服务项目的解析记录推到阿里云。返回 (ok, msg)。"""
    rr = svc.get("rr") or ""
    try:
        existing = dns.search(DomainName=domain, RR=rr)["DomainRecords"]["Record"]
    except Exception as e:
        return False, "查询阿里云失败：" + str(e)
    if existing:
        return True, "阿里云已有该记录"
    res = dns.add(RR=rr, DomainName=domain, Type=svc.get("type") or "CNAME",
                  Value=svc.get("value") or "", Line="default", TTL="600")
    if isinstance(res, dict) and res.get("RequestId"):
        return True, "已推送到阿里云"
    return False, (res or {}).get("Message") or (res or {}).get("msg") or "推送失败"


def _online_tail(store, steps):
    """一键上线的后半段：确保 nginx 存在 → 生成配置生效 → include 缺失自动补。
    steps 会被原地追加。返回 (ok, pending)。"""
    oke, se = _ensure_nginx(store)
    steps.extend(se)
    if not oke:
        return False, False
    oka, ma, pending = _apply_nginx(store)
    steps.append("nginx：" + ma)
    if not oka:
        return False, False
    if not pending and nginx_status(store).get("included") is False:
        okf, mf = _fix_include()
        steps.append(mf)
        if not okf:
            return False, False
    return True, pending


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
        if path == "/api/nginx/status":
            st = {"ok": True}
            st.update(nginx_status(store))
            return self._send(200, st)
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
            if not check_password(body.get("confirm_password") or ""):
                return self._send(200, {"ok": False, "msg": "删除需输入面板登录密码确认，密码不对或未输入，已取消"})
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
            if not check_password(body.get("confirm_password") or ""):
                return self._send(200, {"ok": False, "msg": "删除需输入面板登录密码确认，密码不对或未输入，已取消"})
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
                "https": bool(body.get("https")),
            }
            if not svc["domain"] or not svc["rr"]:
                return self._send(200, {"ok": False, "msg": "主域名和前缀不能为空"})
            if not svc["intro"]:
                return self._send(200, {"ok": False, "msg": "内容介绍必填：写清楚这个服务是干什么的"})
            if not svc["value"]:
                svc["value"] = "tyokantei.3322.org" if svc["type"] == "CNAME" else svc["lan_ip"]
            key = svc["domain"] + "|" + svc["rr"]
            for s in store.get("services") or []:
                if s["domain"] + "|" + s["rr"] == key and s.get("online_at"):
                    svc["online_at"] = s["online_at"]
            store["services"] = [s for s in (store.get("services") or [])
                                 if s["domain"] + "|" + s["rr"] != key]
            store["services"].append(svc)
            save_store(store)
            return self._send(200, {"ok": True, "msg": "项目已保存"})

        if path == "/api/services/delete":
            if not check_password(body.get("confirm_password") or ""):
                return self._send(200, {"ok": False, "msg": "删除需输入面板登录密码确认，密码不对或未输入，已取消"})
            key = (body.get("domain") or "").strip() + "|" + (body.get("rr") or "").strip()
            store["services"] = [s for s in (store.get("services") or [])
                                 if s["domain"] + "|" + s["rr"] != key]
            save_store(store)
            return self._send(200, {"ok": True, "msg": "项目已删除（仅删面板清单，阿里云记录不动）"})

        if path == "/api/nginx/settings":
            ng = store.setdefault("nginx", {})
            try:
                if body.get("listen"):
                    ng["listen"] = int(body["listen"])
                if body.get("panel_port"):
                    ng["panel_port"] = int(body["panel_port"])
            except Exception:
                return self._send(200, {"ok": False, "msg": "端口必须是数字"})
            ng["self_host"] = (body.get("self_host") or "").strip()
            if ng["self_host"] and "." not in ng["self_host"]:
                return self._send(200, {"ok": False, "msg": "面板自身域名「%s」不是完整域名，应填如 dns.tyokantei.cn（不要填服务前缀），未保存" % ng["self_host"]})
            if body.get("cert_file") is not None:
                ng["cert_file"] = (body.get("cert_file") or "").strip()
            if body.get("key_file") is not None:
                ng["key_file"] = (body.get("key_file") or "").strip()
            if body.get("redirect") is not None:
                try:
                    ng["redirect"] = int(body["redirect"])
                except Exception:
                    return self._send(200, {"ok": False, "msg": "跳转端口必须是数字"})
            save_store(store)
            note = ""
            eff = nginx_settings(store)
            posted_pp = (body.get("panel_port") or "")
            if str(posted_pp).isdigit() and int(posted_pp) != eff["panel_port"]:
                note = "（面板自身端口已自动对齐为实际端口 %d）" % eff["panel_port"]
            return self._send(200, {"ok": True, "msg": "nginx 设置已保存（点「生成配置并生效」后起作用）" + note})

        if path == "/api/nginx/install":
            _run(["apt-get", "update"], timeout=300)
            rc, out = _run(["apt-get", "install", "-y", "nginx", "libnginx-mod-stream"], timeout=600)
            if os.path.exists("/usr/sbin/nginx"):
                return self._send(200, {"ok": True, "msg": "nginx 已安装"})
            return self._send(200, {"ok": False, "msg": "安装失败：" + out.strip()[-300:]})

        if path == "/api/nginx/apply":
            ok, m, pending = _apply_nginx(store)
            if ok and not pending:
                m = "已生效：" + m
            return self._send(200, {"ok": ok, "msg": m, "pending": pending})

        if path == "/api/nginx/fix-include":
            ok, m = _fix_include()
            return self._send(200, {"ok": ok, "msg": m})

        if path == "/api/nginx/migrate":
            st = nginx_settings(store)
            err = nginx_settings_error(st)
            if err:
                return self._send(200, {"ok": False, "msg": err + "，请先改好并保存设置"})
            if PANEL_PORT != st["listen"]:
                return self._send(200, {"ok": False, "msg": "面板当前不在入口端口 %d 上，无需切换" % st["listen"]})
            if not nginx_status(store)["installed"]:
                return self._send(200, {"ok": False, "msg": "nginx 未安装，先点「安装 nginx」"})
            conf = gen_nginx_conf(store)
            try:
                if os.path.exists(NGINX_GEN_CONF):
                    with open(NGINX_GEN_CONF, encoding="utf-8") as f:
                        old = f.read()
                    bak = NGINX_GEN_CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")
                    with open(bak, "w", encoding="utf-8") as f:
                        f.write(old)
                with open(NGINX_GEN_CONF, "w", encoding="utf-8") as f:
                    f.write(conf)
            except Exception as e:
                return self._send(200, {"ok": False, "msg": "写配置失败（面板需以 root 运行）：" + str(e)})
            rc, out = _run(["nginx", "-t"], timeout=30)
            if rc != 0:
                return self._send(200, {"ok": False, "msg": "nginx 配置测试未通过：" + out.strip()[-300:]})
            script = ("sleep 2; kill %d; sleep 1; "
                      "cd %s && nohup %s %s --port %d > /tmp/dnsmgr-panel.log 2>&1 & "
                      "systemctl enable nginx; systemctl restart nginx") % (
                          os.getpid(), BASE, sys.executable,
                          os.path.join(BASE, "app.py"), st["panel_port"])
            try:
                with open("/tmp/dnsmgr-migrate.log", "ab") as lf:
                    subprocess.Popen(["bash", "-c", script], stdout=lf, stderr=lf,
                                     start_new_session=True)
            except Exception as e:
                return self._send(200, {"ok": False, "msg": "启动切换失败：" + str(e)})
            return self._send(200, {"ok": True, "msg": "正在切换：面板重启到 %d，nginx 接管 %d。约 5 秒后用 https://%s:%d 重新打开面板（局域网直连端口 %d）" % (st["panel_port"], st["listen"], st["self_host"] or "dns.tyokantei.cn", st["listen"], st["panel_port"])})

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
            if not check_password(body.get("confirm_password") or ""):
                return self._send(200, {"ok": False, "msg": "删除需输入面板登录密码确认，密码不对或未输入，已取消"})
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
            ok, m = _push_service(dns, domain, svc)
            return self._send(200, {"ok": ok, "msg": m})

        if path == "/api/services/online":
            rr = (body.get("rr") or "").strip()
            svc = next((s for s in (store.get("services") or [])
                        if s["domain"] == domain and s["rr"] == rr), None)
            if not svc:
                return self._send(200, {"ok": False, "msg": "项目不存在"})
            steps = []
            okp, mp = _push_service(dns, domain, svc)
            steps.append("同步阿里云：" + mp)
            if not okp:
                return self._send(200, {"ok": False, "msg": "；".join(steps)})
            try:
                recs = dns.search(DomainName=domain, RR=rr)["DomainRecords"]["Record"]
                if recs and recs[0].get("Status") == "Disable":
                    res = dns.update(RecordId=recs[0]["RecordId"], DomainName=domain, New_Status="Enable")
                    if isinstance(res, dict) and res.get("code") == 0:
                        steps.append("已恢复启用")
            except Exception:
                pass
            okt, pending = _online_tail(store, steps)
            if okt:
                svc["online_at"] = int(time.time())
                save_store(store)
            return self._send(200, {"ok": okt, "pending": pending, "msg": "；".join(steps)})

        if path == "/api/online-all":
            steps, bad = [], 0
            by_domain = {}
            for s in store.get("services") or []:
                by_domain.setdefault(s.get("domain") or "", []).append(s)
            for dmn, svcs in by_domain.items():
                prof2 = profile_for_domain(store, dmn)
                if not prof2:
                    steps.append("%s：没有可用密钥档案，跳过" % dmn)
                    bad += 1
                    continue
                dns2 = dns_client(prof2)
                for s in svcs:
                    okp, mp = _push_service(dns2, dmn, s)
                    steps.append("%s：%s" % (((s.get("rr") or "") + "." + dmn).strip("."), mp))
                    if not okp:
                        bad += 1
            okt, pending = _online_tail(store, steps)
            return self._send(200, {"ok": okt and bad == 0, "pending": pending,
                                    "msg": "；".join(steps)})

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
    global PANEL_PORT
    PANEL_PORT = args.port
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
