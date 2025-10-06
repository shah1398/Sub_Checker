#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import urllib.parse
from time import sleep
from ping3 import ping
from rich import print

# ===== مسیر ذخیره خروجی =====
SAVE_PATH = "/sdcard/Download/Akbar98"
os.makedirs(SAVE_PATH, exist_ok=True)

# پذیرش پروتکل‌هایی که معمولاً استفاده می‌کنی
PROTOCOL_PREFIXES = ["vless://", "trojan://", "ss://", "vmess://", "grpc://"]

# -------------------- تابع پالس (Parse / Pulse) --------------------
def parse_link(link):
    """
    پارس کننده لینک‌های vless:// ، trojan:// و ss:// (نسخه‌ی سازگار با کد الگو)
    خروجی: (proto, parsed_dict) یا (None, None) در صورت خطا
    parsed_dict شامل: protocol, address, port, user (یا id), params (dict), remark, raw
    """
    link = (link or "").strip()
    if not link:
        return None, None

    try:
        proto = link.split("://", 1)[0].lower()
        main_part = link.split("://", 1)[1]
        remark = ""

        # جدا کردن remark (بعد از #)
        if "#" in main_part:
            main_part, remark = main_part.split("#", 1)
            remark = urllib.parse.unquote(remark)

        # جدا کردن پارامترها (بعد از ?)
        if "?" in main_part:
            addr_port, params = main_part.split("?", 1)
            query = urllib.parse.parse_qs(params)
            query = {k: v[0] for k, v in query.items()}
        else:
            addr_port = main_part
            query = {}

        # user@host:port یا host:port
        if "@" in addr_port:
            user, host_port = addr_port.split("@", 1)
        else:
            user = ""
            host_port = addr_port

        # آدرس و پورت
        if ":" in host_port:
            address, port = host_port.split(":", 1)
        else:
            address = host_port
            port = "443"

        # نرمالایز نام پروتکل برای ss
        proto_norm = proto
        if proto == "ss":
            proto_norm = "shadowsocks"
        if proto == "vmess":
            proto_norm = "vmess"

        parsed = {
            "protocol": proto_norm,
            "address": address,
            "port": int(port) if str(port).isdigit() else 443,
            "user": user,
            "id": user,  # برخی توابع از id استفاده می‌کنند
            "params": query,
            "remark": remark or link,
            "raw": link
        }
        return proto_norm, parsed
    except Exception:
        return None, None

# -------------------- استخراج هاست و پینگ --------------------
def extract_host(link):
    """
    استخراج hostname یا ip از لینک (سازگار با vless/trojan/ss/vmess ساده)
    برای ss ساده سعی به دیکد کردن base64 می‌کند (نسخهٔ نه کامل برای همه حالات)
    """
    try:
        if not link:
            return None
        if link.startswith("ss://"):
            # تلاش ساده برای استخراج host از قالب ss://...@host:port
            tail = link[5:]
            # اگر شامل @ باشد، قسمت بعد از @ تا : را بردار
            if "@" in tail:
                try:
                    host_port = tail.rsplit("@", 1)[1]
                    host = host_port.split(":", 1)[0]
                    return host
                except:
                    pass
            # fallback: پیدا کردن اولین host با regex
        m = re.search(r"@([^:/?#\s]+)", link)
        if m:
            return m.group(1)
        m2 = re.search(r"://([^:/?#\s]+)", link)
        if m2:
            return m2.group(1)
    except Exception:
        pass
    return None

def ping_host(host, count=3):
    """
    پینگ با ping3؛ میانگین چند نمونه (برگرداند بر حسب ms)
    """
    if not host:
        return None
    delays = []
    for _ in range(count):
        try:
            r = ping(host, timeout=1.5)  # seconds
            if r is not None:
                delays.append(r * 1000.0)
        except Exception:
            pass
        sleep(0.08)
    return (sum(delays) / len(delays)) if delays else None

def classify_ping(ms):
    """دسته‌بندی ping برای چاپ"""
    if ms is None:
        return "red", "[bold red][BAD][/bold red]"
    try:
        if ms < 150:
            return "green", "[bold green][GOOD][/bold green]"
        elif ms < 300:
            return "yellow", "[bold yellow][WARN][/bold yellow]"
        else:
            return "red", "[bold red][BAD][/bold red]"
    except Exception:
        return "red", "[bold red][BAD][/bold red]"

# -------------------- تابع ساخت فرگمنت بهینه (Fragment V1 optimized) --------------------
def fragment_v1_optimized(raw_configs):
    """
    raw_configs: لیست رشته‌های کانفیگ (هریک یک لینک)
    این تابع برای هر کانفیگ parse_link را اجرا می‌کند و سپس یک fragment دقیق می‌سازد.
    خروجی: لیست دیکشنری‌های fragment (یکی برای هر کانفیگ معتبر)
    """
    fragments = []

    for i, raw in enumerate(raw_configs):
        proto, parsed = parse_link(raw)
        if not parsed:
            # اگر parse نشد، سعی کن حداقل host را استخراج کنی و یک fragment پایه بسازی
            host = extract_host(raw) or "0.0.0.0"
            parsed = {
                "protocol": "vless",
                "address": host,
                "port": 443,
                "user": "",
                "id": "",
                "params": {},
                "remark": raw,
                "raw": raw
            }
            proto = "vless"

        # حالا از parsed استفاده کن تا outbound بسازی
        address = parsed.get("address", "0.0.0.0")
        port = parsed.get("port", 443)
        params = parsed.get("params", {}) or {}
        remark = parsed.get("remark") or raw

        # stream default
        stream = {"sockopt": {"dialerProxy": "fragment"}}
        outbound = None

        if proto == "vless" or proto == "vmess":
            network = params.get("type", "ws")
            security = params.get("security", "tls")
            sni = params.get("sni", params.get("host", address))
            fp = params.get("fp", "chrome")
            alpn = params.get("alpn", "http/1.1").split(",") if params.get("alpn") else ["http/1.1"]
            path = params.get("path", "/")
            host_header = params.get("host", address)

            stream["network"] = network
            stream["security"] = security
            if security in ["tls", "xtls"]:
                stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}
            if network == "ws":
                stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
            elif network == "grpc":
                svc = params.get("serviceName", "")
                stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}

            outbound = {
                "tag": "proxy",
                "protocol": "vless" if proto == "vless" else "vmess",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [{
                            "id": parsed.get("id") or parsed.get("user") or "",
                            "encryption": params.get("encryption", "none"),
                            "flow": params.get("flow", "")
                        }]
                    }]
                },
                "streamSettings": stream
            }

        elif proto == "trojan":
            network = params.get("type", "ws")
            security = params.get("security", "tls")
            sni = params.get("sni", params.get("host", address))
            path = params.get("path", "/")
            host_header = params.get("host", address)
            stream["network"] = network
            stream["security"] = security
            if security in ["tls", "xtls"]:
                stream["tlsSettings"] = {"serverName": sni, "fingerprint": params.get("fp", "chrome"), "alpn": params.get("alpn", "http/1.1").split(",") if params.get("alpn") else ["http/1.1"]}
            if network == "ws":
                stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
            elif network == "grpc":
                svc = params.get("serviceName", "")
                stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}

            outbound = {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{"address": address, "port": port, "password": parsed.get("user") or parsed.get("id") or ""}]},
                "streamSettings": stream
            }

        elif proto == "shadowsocks" or proto == "ss":
            method = params.get("method", "aes-128-gcm")
            outbound = {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": address, "port": port, "method": method, "password": parsed.get("user") or parsed.get("id") or ""}]},
                "streamSettings": {"network": "tcp", "security": "none", "sockopt": {"dialerProxy": "fragment"}}
            }

        else:
            # پروتکل نامشخص — نادیده می‌گیریم
            continue

        # Compose fragment
        fragment = {
            "remarks": remark,
            "log": {"loglevel": "warning"},
            "dns": {
                "servers": [
                    {"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"},
                    {"address": "8.8.8.8", "domains": [f"full:{address}"], "skipFallback": True}
                ],
                "queryStrategy": "UseIP",
                "tag": "dns"
            },
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                 "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True}, "tag": "socks-in"},
                {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"}
            ],
            "outbounds": [
                outbound,
                {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"network": "tcp", "outboundTag": "proxy", "type": "field"}
            ]}
        }

        fragments.append(fragment)

        # چاپ خلاصه خطی برای کاربر
        color_seq = ["green", "yellow", "cyan", "magenta", "red"]
        color = color_seq[i % len(color_seq)]
        print(f"[{color}]{i+1}. {fragment['remarks']} -> {address}:{port} ({proto.upper()})[/{color}]")

    return fragments

# -------------------- MAIN --------------------
def main():
    print("[cyan]Paste your configs (any protocol). Press Ctrl+D to finish:[/cyan]")
    lines = []
    while True:
        try:
            line = input().strip()
            if line:
                lines.append(line)
        except EOFError:
            break

    if not lines:
        print("[red]No configs entered. Exiting.[/red]")
        sys.exit(0)

    # پینگ و فیلتر
    live_configs = []
    ping_results = {}
    print("[cyan]\nChecking ping for all configs (3 samples per host)...[/cyan]")
    for cfg in lines:
        host = extract_host(cfg)
        if not host:
            print(f"[magenta]No host extracted: {cfg}[/magenta]")
            continue
        delay = ping_host(host, count=3)
        ping_results[cfg] = delay
        if delay is None:
            print(f"[red]FAIL {host}[/red]")
        elif delay < 150:
            print(f"[green]GOOD {host} - {delay:.1f} ms[/green]")
            live_configs.append(cfg)
        elif delay < 300:
            print(f"[yellow]WARN {host} - {delay:.1f} ms[/yellow]")
            live_configs.append(cfg)
        else:
            print(f"[red]BAD {host} - {delay:.1f} ms[/red]")

    if not live_configs:
        print("[red]No live configs passed ping. Exiting.[/red]")
        sys.exit(0)

    # تولید فرگمنت برای همه کانفیگ‌های زنده (یک به یک)
    fragments = fragment_v1_optimized(live_configs)

    # ذخیره خروجی
    fname = input("Enter output filename (without extension) [default: fragment_output]: ").strip() or "fragment_output"
    outpath = os.path.join(SAVE_PATH, f"{fname}.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(fragments, f, indent=2, ensure_ascii=False)
    print(f"[bold green]✅ Fragment saved to: {outpath}[/bold green] (count: {len(fragments)})")

if __name__ == "__main__":
    main()