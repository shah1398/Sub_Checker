#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import urllib.parse
from ping3 import ping
from rich import print
from rich.table import Table
from time import sleep

# ===== مسیر ذخیره خروجی =====
SAVE_PATH = "/sdcard/Download/Akbar98"
os.makedirs(SAVE_PATH, exist_ok=True)

protocols = ["vless://", "vmess://", "trojan://", "ss://", "grpc://"]

# -------------------- Helpers / Pulse (parse_link) --------------------
def parse_link(link):
    """
    پارس کننده لینک‌های vless:// ، trojan:// و ss://
    خروجی: (proto, parsed_dict) یا (None, None) در صورت خطا
    parsed_dict شامل:
      - protocol, address, port, user (id), params (dict), remark, raw
    """
    link = link.strip()
    if not any(link.startswith(p) for p in ["vless://", "trojan://", "ss://", "vmess://", "grpc://"]):
        return None, None

    try:
        proto = link.split("://", 1)[0]
        main_part = link.split("://", 1)[1]
        remark = ""

        # جدا کردن remark (بعد از #)
        if "#" in main_part:
            main_part, remark = main_part.split("#", 1)

        # جدا کردن پارامترها (بعد از ?)
        if "?" in main_part:
            addr_port, params = main_part.split("?", 1)
            query = urllib.parse.parse_qs(params)
        else:
            addr_port = main_part
            query = {}

        # جدا کردن user@host:port یا host:port
        if "@" in addr_port:
            user, host_port = addr_port.split("@", 1)
        else:
            user = ""
            host_port = addr_port

        # جدا کردن آدرس و پورت
        if ":" in host_port:
            address, port = host_port.split(":", 1)
        else:
            address = host_port
            port = "443"

        parsed = {
            "protocol": proto,
            "address": address,
            "port": int(port) if port.isdigit() else 443,
            "id": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": urllib.parse.unquote(remark) if remark else link,
            "raw": link,
            "user": user
        }
        return proto, parsed
    except Exception:
        return None, None

# -------------------- استخراج هاست و پینگ --------------------
def extract_host(link):
    try:
        if link.startswith("ss://"):
            # try to decode classic ss://method:pass@host:port or base64 form - best-effort
            try:
                import base64
                main = link[5:].split("#")[0]
                # if looks like base64, decode
                if not ("@" in main and ":" in main):
                    dec = base64.urlsafe_b64decode(main + "===")
                    main = dec.decode(errors="ignore")
                if "@" in main:
                    host_port = main.rsplit("@", 1)[1]
                    host = host_port.split(":")[0]
                    return host
            except Exception:
                pass
        m = re.search(r'@([^:/?#\s]+)', link)
        if m:
            return m.group(1)
        # fallback: try after protocol
        m2 = re.search(r'://([^:/?#\s]+)', link)
        if m2:
            return m2.group(1)
    except Exception:
        pass
    return None

def ping_host(host, count=3):
    """
    returns average ms or None
    uses ping3 (returns seconds)
    """
    delays = []
    for _ in range(count):
        try:
            d = ping(host, timeout=1.5)
            if d is not None:
                delays.append(d * 1000.0)
        except Exception:
            pass
        sleep(0.12)
    return sum(delays) / len(delays) if delays else None

def classify_ping(ping_ms):
    if ping_ms is None:
        return "red", "[bold red][BAD][/bold red]"
    if ping_ms < 150:
        return "green", "[bold green][GOOD][/bold green]"
    if ping_ms < 300:
        return "yellow", "[bold yellow][WARN][/bold yellow]"
    return "red", "[bold red][BAD][/bold red]"

# -------------------- Fragment V2 Optimized --------------------
def fragment_v2_optimized(parsed_configs, ping_results=None):
    """
    ورودی: لیست parsed dicts (هر آیتم از parse_link بازگشتی parsed dict است)
    خروجی: لیست fragment objects (یک fragment برای تقریباً هر parsed entry)
    تابع با parse_link و ساختار ping_results هماهنگ است.
    """
    fragments = []

    for i, parsed in enumerate(parsed_configs, start=1):
        if not parsed or not isinstance(parsed, dict):
            # skip invalid item but continue to keep processing others
            continue

        proto = parsed.get("protocol", "vless")
        address = parsed.get("address", "0.0.0.0")
        port = parsed.get("port", 443)
        user_id = parsed.get("id", parsed.get("user", ""))
        params = parsed.get("params", {}) or {}
        remark = parsed.get("remark", f"{proto}_{i}")
        raw = parsed.get("raw", "")

        # ping info if present
        status, ping_val = (None, None)
        if ping_results and raw in ping_results:
            status, ping_val = ping_results[raw]
        ping_str = f"{ping_val:.2f} ms" if isinstance(ping_val, (int, float)) else "NO REPLY"
        remark_with_ping = f"{remark} | {ping_str} | {status.upper() if status else ''}"

        # inbounds
        inbounds_block = [
            {"port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
             "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True},
             "tag": "socks-in"},
            {"port": 10853, "protocol": "dokodemo-door",
             "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53},
             "tag": "dns-in"}
        ]

        routing_block = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"network": "tcp", "outboundTag": "proxy", "type": "field"}
            ]
        }

        # prepare stream settings common logic
        network = params.get("type", "ws")
        security = params.get("security", "tls")
        sni = params.get("sni", params.get("host", address))
        fp = params.get("fp", "chrome")
        alpn = params.get("alpn", "http/1.1").split(",") if "alpn" in params else ["http/1.1"]
        path = params.get("path", "/")
        host_header = params.get("host", address)

        outbound = None

        if proto in ["vless", "vmess", "grpc"]:
            stream = {"network": network if proto != "grpc" else "grpc", "security": security, "sockopt": {"dialerProxy": "fragment"}}
            if network == "ws":
                stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
            elif network == "grpc":
                svc = params.get("serviceName", "")
                stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}
            if security in ["tls", "xtls"]:
                stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}

            outbound = {
                "tag": "proxy",
                "protocol": proto,
                "settings": {
                    # for vmess/vless use vnext shape, keep compatibility
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [{
                            "id": user_id or "",
                            "encryption": params.get("encryption", "none"),
                            "flow": params.get("flow", "")
                        }]
                    }]
                },
                "streamSettings": stream
            }

        elif proto == "trojan":
            stream = {"network": network, "security": security, "sockopt": {"dialerProxy": "fragment"}}
            if network == "ws":
                stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
            elif network == "grpc":
                svc = params.get("serviceName", "")
                stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}
            if security in ["tls", "xtls"]:
                stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}

            outbound = {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{"address": address, "port": port, "password": user_id or "", "flow": params.get("flow", "")}]},
                "streamSettings": stream
            }

        elif proto in ["ss", "shadowsocks"]:
            method = params.get("method", "aes-128-gcm")
            outbound = {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": address, "port": port, "method": method, "password": user_id or ""}]},
                "streamSettings": {"network": "tcp", "security": "none", "sockopt": {"dialerProxy": "fragment"}}
            }

        else:
            # unsupported proto - skip
            continue

        fragment = {
            "remarks": remark_with_ping,
            "log": {"loglevel": "warning"},
            "inbounds": inbounds_block,
            "outbounds": [
                outbound,
                {
                    "tag": "fragment",
                    "protocol": "freedom",
                    "settings": {
                        "fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"},
                        "domainStrategy": "UseIPv4v6"
                    }
                }
            ],
            "routing": routing_block
        }

        fragments.append(fragment)

    return fragments

# -------------------- Main program --------------------
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
        print("[red]No configs entered[/red]")
        sys.exit(0)

    # پینگ و فیلتر کردن
    live_configs = []
    ping_results = {}  # raw -> (status, ping_ms)
    print("[cyan]\nChecking ping for all configs (3 samples per host)...[/cyan]")
    for cfg in lines:
        host = extract_host(cfg)
        if not host:
            print(f"[magenta]No host parsed: {cfg}[/magenta]")
            continue
        delay = ping_host(host, count=3)
        status, label = classify_ping(delay)
        ping_results[cfg] = (status, delay)
        if delay is None:
            print(f"[red]FAIL {host}[/red]")
        elif delay < 150:
            print(f"[green]GOOD {host} - {delay:.1f}ms[/green]")
            live_configs.append(cfg)
        elif delay < 300:
            print(f"[yellow]WARN {host} - {delay:.1f}ms[/yellow]")
            live_configs.append(cfg)
        else:
            print(f"[red]BAD {host} - {delay:.1f}ms[/red]")

    if not live_configs:
        print("[red]No live configs passed ping. Exiting.[/red]")
        sys.exit(0)

    # parse each live config with parse_link (pulse)
    parsed_list = []
    for cfg in live_configs:
        proto, parsed = parse_link(cfg)
        if parsed:
            parsed_list.append(parsed)
        else:
            # try to construct a minimal parsed dict fallback so fragment_v2_optimized can still create fragments
            host = extract_host(cfg) or "0.0.0.0"
            parsed_list.append({
                "protocol": proto or "vless",
                "address": host,
                "port": 443,
                "id": "",
                "params": {},
                "remark": cfg,
                "raw": cfg
            })

    # generate fragments using optimized fragment_v2
    fragments = fragment_v2_optimized(parsed_list, ping_results=ping_results)

    # save output
    fname = input("Enter output filename (without extension) [fragment_v2_out]: ").strip() or "fragment_v2_out"
    path = os.path.join(SAVE_PATH, f"{fname}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(fragments, f, indent=2, ensure_ascii=False)
        print(f"[green]✅ Fragment saved to: {path}[/green]")
    except Exception as e:
        print(f"[red]Failed to save file: {e}[/red]")

if __name__ == "__main__":
    main()