#!/usr/bin/env python3
# fragment_builder_enhanced.py
# نسخه ارتقا یافته تابع ساخت فرگمنت — خروجی JSON کامل‌تر و استانداردتر

import json
import sys
import os
import re
from urllib.parse import parse_qs, unquote
import base64

GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# مسیر پیش‌فرض ذخیره — در صورت نیاز تغییر دهید
SAVE_PATH = "/storage/emulated/0/Download/almasi98"

# ------------------ Helpers ------------------
def safe_b64_decode(data: str):
    try:
        pad = len(data) % 4
        if pad:
            data += "=" * (4 - pad)
        return base64.urlsafe_b64decode(data).decode("utf-8")
    except:
        return None

def to_int(v, default=443):
    try:
        return int(v)
    except:
        return default

def _norm_bool(v):
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes", "on")

# ------------------ Parsers ------------------
def parse_vless(link: str):
    try:
        rest = link.split("://", 1)[1]
        remark = ""
        if "#" in rest:
            rest, remark = rest.split("#", 1)
        if "?" in rest:
            addr_port, params = rest.split("?", 1)
            query = parse_qs(params)
        else:
            addr_port = rest
            query = {}
        if "@" in addr_port:
            user, host_port = addr_port.split("@", 1)
        else:
            user = ""
            host_port = addr_port
        if ":" in host_port:
            address, port = host_port.split(":", 1)
        else:
            address = host_port
            port = "443"
        return {
            "protocol": "vless",
            "raw": link,
            "address": address,
            "port": to_int(port, 443),
            "user": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": unquote(remark)
        }
    except:
        return None

def parse_trojan(link: str):
    try:
        rest = link.split("://",1)[1]
        remark = ""
        if "#" in rest:
            rest, remark = rest.split("#",1)
        if "?" in rest:
            addr_port, params = rest.split("?",1)
            query = parse_qs(params)
        else:
            addr_port = rest
            query = {}
        if "@" in addr_port:
            passwd, host_port = addr_port.split("@",1)
        else:
            passwd = ""
            host_port = addr_port
        if ":" in host_port:
            address, port = host_port.split(":",1)
        else:
            address = host_port
            port = "443"
        return {
            "protocol":"trojan",
            "raw":link,
            "address":address,
            "port":to_int(port,443),
            "user":passwd,
            "params":{k:v[0] for k,v in query.items()},
            "remark":unquote(remark)
        }
    except:
        return None

def parse_ss(link: str):
    try:
        main = link.split("://",1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
        remark = unquote(remark)
        # long form: method:pass@host:port
        if "@" in main and ":" in main.split("@",1)[1]:
            method_pass, host_port = main.split("@",1)
            if ":" in method_pass:
                method,password = method_pass.split(":",1)
            else:
                method,password = method_pass,""
            if ":" in host_port:
                address, port = host_port.split(":",1)
            else:
                address, port = host_port, "443"
            return {
                "protocol":"ss",
                "raw":link,
                "address":address,
                "port":to_int(port,443),
                "user":password,
                "method":method,
                "params":{},
                "remark":remark
            }
        else:
            decoded = safe_b64_decode(main)
            if decoded and "@" in decoded:
                method_pass, host_port = decoded.split("@",1)
                if ":" in method_pass:
                    method,password = method_pass.split(":",1)
                else:
                    method,password = method_pass,""
                if ":" in host_port:
                    address, port = host_port.split(":",1)
                else:
                    address, port = host_port, "443"
                return {
                    "protocol":"ss",
                    "raw":link,
                    "address":address,
                    "port":to_int(port,443),
                    "user":password,
                    "method":method,
                    "params":{},
                    "remark":remark
                }
    except:
        return None
    return None

def parse_config(conf: str):
    conf = conf.strip()
    if conf.startswith("vless://"): return parse_vless(conf)
    if conf.startswith("trojan://"): return parse_trojan(conf)
    if conf.startswith("ss://"): return parse_ss(conf)
    return None

# ------------------ Fragment Builder (Enhanced) ------------------

def _parse_alpn(value):
    if not value:
        return ["h2","http/1.1"]
    return [v.strip() for v in re.split(r"[,;\s]+", value) if v.strip()]

def _make_tls_settings(params, address):
    # اگر پارامترها خالی باشند، None بازگردان
    sni = params.get("sni") or params.get("host") or address
    fp = params.get("fp", params.get("fingerprint", "chrome"))
    alpn = _parse_alpn(params.get("alpn"))
    allow_insecure = _norm_bool(params.get("allowInsecure"))
    show = _norm_bool(params.get("show"))
    # برگشت دیکشنری کامل TLS (همیشه برگشت داده می‌شود چون sni/fp را حداقل مقداردهی کردیم)
    return {
        "serverName": sni,
        "fingerprint": fp,
        "alpn": alpn,
        "allowInsecure": allow_insecure,
        "show": show
    }

def build_fragment(parsed, ping_results=None):
    """
    خروجی: یک JSON کامل‌شده برای هر فرگمنت
    - استخراج حداکثر پارامترها از parsed['params']
    - اضافه کردن outbounds: proxy, fragment, direct, block
    - inbounds کامل‌تر (socks, http, dokodemo)
    - routing برای tcp/udp و dns
    """
    if not parsed:
        return None

    proto = parsed["protocol"]
    address = parsed["address"]
    port = parsed["port"]
    remark = parsed.get("remark") or f"{proto} fragment"
    params = parsed.get("params", {})

    # --- inbounds استاندارد و کامل ---
    inbounds_block = [
        {
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
            "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False},
            "tag": "socks-in"
        },
        {
            "port": 10809,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False},
            "tag": "http-in"
        },
        {
            "port": 10853,
            "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1", "network": "tcp,udp", "port": 53},
            "tag": "dns-in"
        }
    ]

    # --- routing کامل ---
    routing_block = {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
            {"network": "tcp", "outboundTag": "proxy", "type": "field"},
            {"network": "udp", "outboundTag": "proxy", "type": "field"},
        ]
    }

    # --- آماده‌سازی streamSettings بر اساس params ---
    # پیش‌فرض‌ها
    network = params.get("type") or params.get("network") or "ws"
    security = params.get("security") or ("tls" if network in ("ws","grpc","h2") else "none")
    sockopt_base = {"dialerProxy": "fragment", "tcpNoDelay": True, "tcpKeepAliveIdle": 100}

    stream = {"sockopt": sockopt_base}

    # WebSocket
    if network == "ws":
        path = params.get("path", "/")
        host_header = params.get("host", address)
        stream.update({
            "network": "ws",
            "security": security,
            "wsSettings": {"path": path, "headers": {"Host": host_header}}
        })
    # gRPC
    elif network == "grpc":
        svc = params.get("serviceName") or params.get("service", "")
        grpc_settings = {"serviceName": svc} if svc else {"multiMode": False}
        stream.update({
            "network": "grpc",
            "security": security,
            "grpcSettings": grpc_settings
        })
    # HTTP/2 (h2) - نمایشی
    elif network in ("h2","http2"):
        path = params.get("path", "/")
        host_header = params.get("host", address)
        stream.update({
            "network": "h2",
            "security": security,
            "httpSettings": {"path": path, "host": [host_header]}
        })
    else:
        # fallback
        stream.update({"network": network, "security": security})

    # TLS settings (اگر security از نوع tls یا xtls باشد)
    if security and security.lower() in ("tls","xtls"):
        stream["tlsSettings"] = _make_tls_settings(params, address)

    # --- ساخت outbound proxy بر اساس پروتکل ---
    outbound = None
    if proto == "vless":
        user_id = parsed.get("user") or params.get("id") or ""
        encryption = params.get("encryption", "none")
        flow = params.get("flow", "")
        vnext = [{"address": address, "port": port, "users": [{"id": user_id, "encryption": encryption, "flow": flow}]}]
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": vnext},
            "streamSettings": stream
        }
    elif proto == "trojan":
        password = parsed.get("user") or params.get("password","")
        flow = params.get("flow","")
        servers = [{"address": address, "port": port, "password": password, "flow": flow}]
        outbound = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {"servers": servers},
            "streamSettings": stream
        }
    elif proto == "ss":
        method = parsed.get("method") or params.get("method","aes-128-gcm")
        password = parsed.get("user") or params.get("password","")
        servers = [{"address": address, "port": port, "method": method, "password": password}]
        outbound = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {"servers": servers},
            "streamSettings": {"network": "tcp", "security": "none", "sockopt": sockopt_base}
        }
    else:
        # اگر پروتکل ناشناخته بود، بازگردان None
        return None

    # --- fragment outbound استاندارد با تنظیمات متعارف برای عبور از DPI ---
    fragment_outbound = {
        "tag": "fragment",
        "protocol": "freedom",
        "settings": {
            "fragment": {
                # تنظیمات پیشنهادی: بسته‌های کوچک و فاصله معقول برای مخفی‌سازی
                "packets": params.get("fragment_packets","tlshello"),
                "length": params.get("fragment_length","10-20"),
                "interval": params.get("fragment_interval","10-20")
            },
            "domainStrategy": params.get("fragment_domainStrategy","UseIPv4v6")
        },
        "streamSettings": {
            "sockopt": {"tcpNoDelay": True, "tcpKeepAliveIdle": 100}
        }
    }

    # --- direct و block outbounds ---
    direct_outbound = {"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"AsIs"}}
    block_outbound = {"tag":"block","protocol":"blackhole","settings":{"response":{"type":"http"}}}

    # --- DNS outbound ساده (موقت) ---
    dns_outbound = {
        "tag": "dns-out",
        "protocol": "dns",
        "settings": {}
    }

    # ترکیب نهایی
    outbounds = [outbound, fragment_outbound, direct_outbound, block_outbound, dns_outbound]

    # لاگ کامل‌تر (فیلدهای access و error را خالی نگه می‌داریم مگر بخواهید مسیر بدهید)
    log_block = {"loglevel": "warning", "access": "", "error": ""}

    result = {
        "remarks": remark,
        "log": log_block,
        "inbounds": inbounds_block,
        "outbounds": outbounds,
        "routing": routing_block
    }

    return result

# ------------------ Save Output ------------------
def save_output(choice, configs):
    os.makedirs(SAVE_PATH, exist_ok=True)
    filename = input(GREEN + "Enter file name (without extension): " + RESET).strip()
    if not filename:
        print(YELLOW + "❌ Invalid file name." + RESET)
        return None

    extension = "txt"
    content = []

    if choice == "1":
        parsed = [parse_config(c) for c in configs]
        parsed = [p for p in parsed if p]
        fragments = [build_fragment(p) for p in parsed if p]
        # حذف موارد None در صورت بروز خطا
        fragments = [f for f in fragments if f]
        extension = "json"
        content = fragments
    else:
        content = configs

    result_path = os.path.join(SAVE_PATH, f"{filename}.{extension}")
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            if extension == "json":
                json.dump(content, f, ensure_ascii=False, indent=2)
            else:
                for item in content:
                    f.write(item + "\n")
        print(GREEN + f"✅ Saved: {result_path}" + RESET)
        return result_path
    except Exception as e:
        print(YELLOW + f"⚠️ Error writing file: {e}" + RESET)
        return None

# ------------------ Main ------------------
def main():
    print(BLUE + "Paste your configs, end with Ctrl+D:" + RESET)
    input_text = sys.stdin.read().strip()
    lines = [l.strip() for l in input_text.splitlines() if l.strip()]

    while True:
        print(BLUE + "\nChoose output format (0 to exit):" + RESET)
        print("1) Fragmented VLESS/Trojan/SS (JSON)")
        print("2) Raw links (TXT)")

        choice = input("Option: ").strip()
        if choice == "0":
            print(GREEN + "Exiting." + RESET)
            break

        save_output(choice, lines)

if __name__ == "__main__":
    main()
