#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import time
import random
from urllib.parse import unquote, parse_qs
from typing import List, Dict, Any, Optional
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# ==================== Settings ====================
SAVE_DIR = "/storage/emulated/0/Download/almasi98"
os.makedirs(SAVE_DIR, exist_ok=True)
MAX_THREADS = 20
PING_COUNT = 3
MAX_COMBO = 50

# ==================== Helpers ====================
def extract_host(cfg: str) -> Optional[str]:
    m = re.search(r"@([^:/?#\s]+)", cfg)
    if m:
        return m.group(1)
    m2 = re.search(r"://([^:/?#\s]+)", cfg)
    return m2.group(1) if m2 else None

def extract_protocol(cfg: str) -> str:
    return cfg.split("://")[0].lower() if "://" in cfg else "unknown"

def ping_host(host: str) -> Optional[float]:
    try:
        output = subprocess.check_output(["ping","-c","3","-W","1",host], stderr=subprocess.DEVNULL).decode(errors="ignore")
        m = re.search(r"rtt min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)", output)
        if m:
            return float(m.group(1))
        m2 = re.search(r"min/avg/max = [\d.]+/([\d.]+)", output)
        if m2:
            return float(m2.group(1))
        return None
    except Exception:
        return None

def ping_ping3(host: str) -> Optional[float]:
    results_list = []
    for _ in range(PING_COUNT):
        try:
            r = ping(host, timeout=1, unit="ms")
            if r is not None:
                results_list.append(r)
        except Exception:
            continue
    return (sum(results_list) / len(results_list)) if results_list else None

def classify_ping(ms: Optional[float]):
    if ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    try:
        m = float(ms)
    except Exception:
        return "bad", "[bold red][BAD][/bold red]"
    if m < 150:
        return "good", "[bold green][GOOD][/bold green]"
    if m < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ==================== Input ====================
print("[cyan]Enter your configs line by line (Ctrl+D when done):[/cyan]")
configs: List[str] = []
while True:
    try:
        line = input()
        if line and line.strip():
            configs.append(line.strip())
    except EOFError:
        break

if not configs:
    print("[red]No configs entered![/red]")
    exit()

# ==================== Ping & Stats ====================
protocol_count: Dict[str, int] = {}
# IMPORTANT: ensure results is a LIST (not a dict). keep this name to match your main.
results: List[Dict[str, Any]] = []

def process(cfg: str):
    host = extract_host(cfg)
    if not host:
        return cfg, None, None, None, None
    sub_ms = ping_host(host)
    ping3_ms = ping_ping3(host)
    status_sub, _ = classify_ping(sub_ms)
    status_ping3, _ = classify_ping(ping3_ms)
    return cfg, sub_ms, ping3_ms, status_sub, status_ping3

with Progress(
    SpinnerColumn(),
    "[progress.description]{task.description}",
    BarColumn(),
    "[progress.percentage]{task.percentage:>3.0f}%",
    TimeRemainingColumn()
) as prog:
    task = prog.add_task("[cyan]Pinging hosts...", total=len(configs))
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(process, cfg): cfg for cfg in configs}
        for fut in as_completed(futures):
            cfg, sub_ms, ping3_ms, status_sub, status_ping3 = fut.result()
            proto = extract_protocol(cfg)
            # if both statuses are None -> ignored
            if status_sub is None and status_ping3 is None:
                print(f"[yellow]Ignored:[/yellow] {cfg}")
                prog.update(task, advance=1)
                continue
            protocol_count[proto] = protocol_count.get(proto, 0) + 1
            # append to results (results is list)
            results.append({
                "config": cfg,
                "protocol": proto,
                "sub_ms": sub_ms,
                "ping3_ms": ping3_ms,
                "status_sub": status_sub,
                "status_ping3": status_ping3
            })
            prog.update(task, advance=1)

# ==================== Summary ====================
table = Table(title="Configs Summary")
table.add_column("Config")
table.add_column("Proto")
table.add_column("Sub(ms)")
table.add_column("Sub Status")
table.add_column("Ping3(ms)")
table.add_column("Ping3 Status")
for r in results:
    table.add_row(
        r["config"],
        r["protocol"].upper(),
        str(int(r["sub_ms"])) if isinstance(r["sub_ms"], (int, float)) else "-",
        (r["status_sub"] or "-").upper(),
        f"{r['ping3_ms']:.2f}" if isinstance(r["ping3_ms"], (int, float)) else "-",
        (r["status_ping3"] or "-").upper()
    )
print(table)

proto_table = Table(title="Protocol Counts")
proto_table.add_column("Proto")
proto_table.add_column("Count")
for k, v in protocol_count.items():
    proto_table.add_row(k.upper(), str(v))
print(proto_table)

# ==================== Parser ====================
def parse_link(link: str):
    """
    دقیقاً تابع پارس از کد مادر برای استخراج اطلاعات لینک
    بازگشت (proto, parsed_dict) یا (None, None)
    """
    link = link.strip()
    proto = None
    parsed = None
    try:
        if link.startswith("vless://"):
            proto = "vless"
        elif link.startswith("trojan://"):
            proto = "trojan"
        elif link.startswith("ss://"):
            proto = "ss"
        else:
            return None, None
        main = link.split("://", 1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#", 1)
        if "?" in main:
            addr, params = main.split("?", 1)
            query = parse_qs(params)
        else:
            addr = main
            query = {}
        if "@" in addr:
            user, host_port = addr.split("@", 1)
        else:
            user = ""
            host_port = addr
        if ":" in host_port:
            address, port = host_port.split(":", 1)
        else:
            address = host_port
            port = "443"
        parsed = {
            "protocol": proto,
            "address": address,
            "port": int(port) if port.isdigit() else 443,
            "user": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": unquote(remark) or address,
            "raw": link
        }
    except Exception:
        parsed = None
    return proto, parsed
# ==================== Fragment Builder ====================
def build_fragments(cfgs: List[str]):
    frags: List[Dict[str, Any]] = []
    for i, cfg in enumerate(cfgs):
        proto, parsed = parse_link(cfg)
        if not parsed:
            host = extract_host(cfg) or "0.0.0.0"
            parsed = {
                "protocol": "ss",
                "address": host,
                "port": 443,
                "user": "user",
                "params": {},
                "remark": cfg,
                "raw": cfg
            }
            proto = "ss"

        remark = parsed.get("remark") or f"Config{i+1}"
        addr = parsed.get("address", "0.0.0.0")
        port = parsed.get("port", 443)
        params = parsed.get("params", {}) or {}
        user_id = parsed.get("user", parsed.get("id", "user"))

        # determine network/security
        network = params.get("type") or params.get("network") or "ws"
        security = params.get("security")
        if not security:
            if str(params.get("tls", "")).lower() in ("tls", "true", "1"):
                security = "tls"
            else:
                security = "none"

        path = params.get("path", "/")
        sni = params.get("sni") or params.get("host") or addr
        fp = params.get("fp", "chrome")
        alpn = [p.strip() for p in (params.get("alpn") or "").split(",") if p.strip()] or ["http/1.1"]
        host_header = params.get("host", addr)

        dns = {
            "servers": [
                {"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"},
                {"address": "8.8.8.8", "domains": [f"full:{addr}"], "skipFallback": True}
            ],
            "queryStrategy": "UseIP",
            "tag": "dns"
        }

        inb = [
            {"port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
             "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True},
             "tag": "socks-in"},
            {"port": 10853, "protocol": "dokodemo-door",
             "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53},
             "tag": "dns-in"}
        ]

        routing = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"network": "tcp", "outboundTag": "proxy", "type": "field"},
                {"network": "udp", "outboundTag": "proxy", "type": "field"}
            ]
        }

        # build outbound by protocol
        if proto == "vless":
            outbound = {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {"address": addr, "port": int(port),
                         "users": [{"id": user_id, "encryption": params.get("encryption", "none"), "flow": params.get("flow", "")}]}
                    ]
                },
                "streamSettings": {"network": network, "security": security, "sockopt": {"dialerProxy": "fragment"}}
            }
            if network == "ws":
                outbound["streamSettings"]["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
            if security in ("tls", "xtls"):
                outbound["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}

        elif proto == "trojan":
            outbound = {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{"address": addr, "port": int(port), "password": parsed.get("user", ""), "flow": params.get("flow", "")}]},
                "streamSettings": {"network": network, "security": security, "sockopt": {"dialerProxy": "fragment"}}
            }
            if network == "ws":
                outbound["streamSettings"]["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
            if security in ("tls", "xtls"):
                outbound["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}

        elif proto == "ss":
            method = parsed.get("method") or params.get("method") or "aes-128-gcm"
            outbound = {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": addr, "port": int(port), "method": method, "password": parsed.get("user", "")}]},
                "streamSettings": {"network": "tcp", "security": "none", "sockopt": {"dialerProxy": "fragment"}}
            }

        else:
            # fallback to vless-ish
            outbound = {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": addr, "port": int(port), "users": [{"id": user_id, "encryption": "none", "flow": ""}]}]},
                "streamSettings": {"network": "ws", "security": "tls", "sockopt": {"dialerProxy": "fragment"},
                                   "tlsSettings": {"serverName": sni, "fingerprint": fp, "alpn": alpn},
                                   "wsSettings": {"path": path, "headers": {"Host": host_header}}}
            }

        frag = {
            "remarks": remark,
            "log": {"loglevel": "warning"},
            "dns": dns,
            "inbounds": inb,
            "outbounds": [
                outbound,
                {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}
            ],
            "routing": routing
        }

        frags.append(frag)
    return frags

# ==================== Combos ====================
def strip_proto(link: str) -> str:
    return link.split("://", 1)[1] if "://" in link else link

def combo2(cfgs: List[str], cap: int = MAX_COMBO):
    n = len(cfgs)
    if n < 2:
        return []
    indices = [(i, j) for i in range(n) for j in range(i + 1, n)]
    random.shuffle(indices)
    combos: List[str] = []
    seen = set()
    for i, j in indices:
        combo = f"{cfgs[i]}+{cfgs[j]}"
        if combo not in seen:
            combos.append(combo)
            seen.add(combo)
        if len(combos) >= cap:
            break
    return combos

def combo3(cfgs: List[str], cap: int = MAX_COMBO):
    n = len(cfgs)
    if n < 3:
        return []
    cands = []
    limit = cap * 8
    for a in range(n):
        for b in range(a + 1, n):
            for c in range(b + 1, n):
                cands.append((a, b, c))
                if len(cands) >= limit:
                    break
            if len(cands) >= limit:
                break
        if len(cands) >= limit:
            break
    random.shuffle(cands)
    combos: List[str] = []
    seen = set()
    for i, j, k in cands:
        A = cfgs[i]
        B = cfgs[j]
        C = cfgs[k]
        tail = strip_proto(C)
        combo = f"{A}+{B}+ss://{tail}"
        if combo in seen:
            continue
        seen.add(combo)
        combos.append(combo)
        if len(combos) >= cap:
            break
    return combos

# ==================== Output Menu ====================
def ask_file(def_name: str, ext: str = ".txt"):
    n = input(f"Enter filename (default {def_name}): ").strip()
    n = n or def_name
    if not n.endswith(ext):
        n += ext
    return os.path.join(SAVE_DIR, n)

def outputs(configs: List[Dict[str, Any]]):
    while True:
        print("\n[cyan]Choose output:[/cyan]")
        print("1) VLESS")
        print("2) TROJAN")
        print("3) SHADOWSOCKS")
        print("4) Combo-2")
        print("5) Combo-3")
        print("6) Fragment JSON")
        print("0) Exit")
        choice = input("Choice: ").strip()
        if choice == "0":
            break
        raw = [c["remark"] for c in configs]
        if choice == "1":
            proto = "vless"
        elif choice == "2":
            proto = "trojan"
        elif choice == "3":
            proto = "ss"
        else:
            proto = None

        if proto:
            lst = [c["remark"] for c in configs if c.get("protocol") == proto]
            path = ask_file(proto)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lst))
            print(f"[green]Saved {proto} ({len(lst)}) -> {path}[/green]")

        elif choice == "4":
            lst = combo2(raw)
            path = ask_file("combo2")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lst))
            print(f"[green]Saved Combo-2 ({len(lst)}) -> {path}[/green]")

        elif choice == "5":
            lst = combo3(raw)
            path = ask_file("combo3")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lst))
            print(f"[green]Saved Combo-3 ({len(lst)}) -> {path}[/green]")

        elif choice == "6":
            frags = build_fragments(raw)
            path = ask_file("fragment", ".json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(frags, f, ensure_ascii=False, indent=2)
            print(f"[green]Saved {len(frags)} fragments -> {path}[/green]")
        else:
            print("[red]Invalid choice[/red]")

# ==================== MAIN ====================
if __name__ == "__main__":
    accepted = [r["config"] for r in results if (r.get("status_sub") and r.get("status_sub") != "bad") or (r.get("status_ping3") and r.get("status_ping3") != "bad")]
    configs_dicts: List[Dict[str, Any]] = []
    for cfg in accepted:
        configs_dicts.append({
            "protocol": extract_protocol(cfg),
            "address": extract_host(cfg) or "example.com",
            "port": 443,
            "id": "uuid",
            "remark": cfg,
            "params": {}
        })
    outputs(configs_dicts)
