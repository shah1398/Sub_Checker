#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# یکپارچه: هستهٔ پینگ (subprocess + ping3) جایگزین شد و نتایج برای توابع فرگمنت آماده می‌شود.

import os
import re
import subprocess
import time
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn
from ping3 import ping

# ---------------- Settings ----------------
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAX_THREADS = 20
PING3_COUNT = 3  # تعداد نمونه‌های ping3
PROTOCOLS = ["vless://", "vmess://", "trojan://", "ss://", "grpc://"]

# ---------------- Helpers (host/proto extraction) ----------------
def extract_host(config: str) -> Optional[str]:
    # تلاش برای استخراج هاست از قالب user@host:port یا از ss:// base64 pattern
    try:
        if config.startswith("ss://"):
            # تلاش حداقلی برای شناسایی host در ss:// که بخش بعد از @ دارد
            main = config[5:].split("#")[0]
            # اگر base64 نباشد (روش ساده): تلاش برای استخراج @host:port
            if "@" in main:
                host_port = main.rsplit("@", 1)[1]
                host = host_port.split(":", 1)[0]
                return host
        m = re.search(r"@([^:/?#\s]+)", config)
        if m:
            return m.group(1)
        m2 = re.search(r"://([^:/?#\s]+)", config)
        return m2.group(1) if m2 else None
    except Exception:
        return None

def extract_protocol(config: str) -> str:
    if "://" in config:
        return config.split("://", 1)[0].lower()
    return "unknown"

# ---------------- Ping methods ----------------
def ping_subprocess(host: str) -> Optional[float]:
    """Ping using system ping (returns avg ms or None)."""
    try:
        output = subprocess.check_output(
            ["ping", "-c", "3", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        # match avg from rtt min/avg/max/mdev = ...
        m = re.search(r"rtt min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)", output)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return None

def ping_ping3(host: str, count: int = PING3_COUNT) -> Optional[float]:
    """Ping using ping3; returns average in ms (or None)."""
    results = []
    for _ in range(count):
        try:
            r = ping(host, timeout=1, unit="ms")
            if r is not None:
                # ping3 returns milliseconds (if unit="ms")
                results.append(r)
        except Exception:
            continue
    if results:
        return sum(results) / len(results)
    return None

def classify_ping(avg_ms: Optional[float]) -> Tuple[str, str]:
    """Classify: returns (status_key, label_str)."""
    if avg_ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    try:
        ms = float(avg_ms)
    except Exception:
        return "bad", "[bold red][BAD][/bold red]"
    if ms < 150:
        return "good", "[bold green][GOOD][/bold green]"
    if ms < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ---------------- Combined ping core ----------------
def process_config_ping(cfg: str) -> Tuple[str, Optional[float], Optional[float], str, str]:
    """
    For a given raw config string:
      - extract host
      - run subprocess ping and ping3
      - return (cfg, sub_ms, ping3_ms, status_sub, status_ping3)
    """
    host = extract_host(cfg)
    if not host:
        return cfg, None, None, "ignored", "ignored"
    sub_ms = ping_subprocess(host)
    ping3_ms = ping_ping3(host, count=PING3_COUNT)
    status_sub, _ = classify_ping(sub_ms)
    status_ping3, _ = classify_ping(ping3_ms)
    return cfg, sub_ms, ping3_ms, status_sub, status_ping3

# ---------------- Parsing helpers (pulse / parse_link) ----------------
def parse_vless_link(link: str) -> Optional[Dict[str, Any]]:
    try:
        main = link.split("://", 1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#", 1)
            remark = urllib.parse.unquote(remark)
        if "?" in main:
            addr_port, params = main.split("?", 1)
            query = urllib.parse.parse_qs(params)
        else:
            addr_port = main
            query = {}
        if "@" in addr_port:
            user_id, host_port = addr_port.split("@", 1)
        else:
            user_id = ""
            host_port = addr_port
        if ":" in host_port:
            address, port = host_port.split(":", 1)
        else:
            address = host_port
            port = 443
        return {
            "protocol": "vless",
            "address": address,
            "port": int(port) if str(port).isdigit() else 443,
            "id": user_id,
            "params": {k: v[0] for k, v in query.items()},
            "remark": remark or link,
            "raw": link,
            "user": user_id
        }
    except Exception:
        return None

def parse_link_general(link: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Minimal general parser supporting vless/trojan/ss as fallback to feed fragment functions."""
    link = link.strip()
    if link.startswith("vless://"):
        p = parse_vless_link(link)
        return ("vless", p) if p else (None, None)
    if link.startswith("trojan://"):
        try:
            main = link.split("://", 1)[1]
            remark = ""
            if "#" in main:
                main, remark = main.split("#", 1)
                remark = urllib.parse.unquote(remark)
            user_host = main
            user = ""
            host_port = user_host
            if "@" in user_host:
                user, host_port = user_host.split("@", 1)
            addr, port = (host_port.split(":", 1) + ["443"])[:2]
            return ("trojan", {"protocol": "trojan", "address": addr, "port": int(port) if str(port).isdigit() else 443, "user": user, "params": {}, "remark": remark, "raw": link})
        except Exception:
            return (None, None)
    if link.startswith("ss://"):
        try:
            main = link.split("://", 1)[1]
            remark = ""
            if "#" in main:
                main, remark = main.split("#", 1)
                remark = urllib.parse.unquote(remark)
            if "@" in main:
                _, host_port = main.rsplit("@", 1)
                address, port = (host_port.split(":", 1) + ["443"])[:2]
                return ("ss", {"protocol": "ss", "address": address, "port": int(port) if str(port).isdigit() else 443, "id": "", "params": {}, "remark": remark, "raw": link})
        except Exception:
            return (None, None)
    return (None, None)

# ---------------- Fragment functions (kept as in baseline) ----------------
# Fragment V1: expects parsed dicts list
def fragment_v1(configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fragments = []
    for i, cfg in enumerate(configs):
        # ensure keys exist
        address = cfg.get("address", "0.0.0.0")
        port = cfg.get("port", 443)
        params = cfg.get("params", {})
        user_id = cfg.get("id", cfg.get("user", ""))
        network = params.get("type", "ws")
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": user_id,
                        "encryption": params.get("encryption", "none"),
                        "flow": params.get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": network,
                "security": params.get("security", "tls"),
                "sockopt": {"dialerProxy": "fragment"},
                "tlsSettings": {
                    "serverName": params.get("sni", params.get("host", address)),
                    "fingerprint": params.get("fp", "chrome"),
                    "alpn": params.get("alpn", "").split(",") if "alpn" in params else ["http/1.1"]
                },
                "wsSettings": {
                    "path": params.get("path", "/"),
                    "headers": {"Host": params.get("host", address)}
                }
            }
        }

        fragment = {
            "remarks": cfg.get("remark") or f"💦 {i+1} - VLESS",
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
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                    {"network": "tcp", "outboundTag": "proxy", "type": "field"}
                ]
            }
        }
        fragments.append(fragment)
    return fragments

# Fragment V2: expects parsed_configs list; multi-protocol
def fragment_v2(parsed_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fragments = []
    for idx, cfg in enumerate(parsed_configs, 1):
        proto = cfg.get("protocol", "vless")
        server = cfg.get("address")
        port = cfg.get("port")
        uuid = cfg.get("id", "")
        name = cfg.get("remark", f"proxy{idx}")
        tls = cfg.get("params", {}).get("security", "none") == "tls"
        network = cfg.get("params", {}).get("type", "tcp")
        password = cfg.get("params", {}).get("password", "")

        outbound = None
        if proto in ["vless", "vmess"]:
            outbound = {
                "tag": "proxy",
                "protocol": proto,
                "settings": {
                    "vnext": [{"address": server, "port": port, "users": [{"id": uuid, "encryption": "none"}]}]
                },
                "streamSettings": {"network": network, "security": "tls" if tls else "none"}
            }
        elif proto == "trojan":
            outbound = {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{"address": server, "port": port, "password": password}]},
                "streamSettings": {"network": network, "security": "tls" if tls else "none"}
            }
        elif proto in ["ss", "shadowsocks"]:
            outbound = {
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": server, "port": port, "password": password, "method": "aes-128-gcm"}]},
                "streamSettings": {"network": network, "security": "none"}
            }
        else:
            continue

        fragment = {
            "remarks": name,
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"},
                {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "port": 53, "network": "tcp,udp"}, "tag": "dns-in"}
            ],
            "outbounds": [
                outbound,
                {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello","length": "100-200","interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"network": "tcp", "outboundTag": "proxy", "type": "field"}]}
        }

        fragments.append(fragment)
    return fragments

# Fragment V3: accepts raw config strings + ping_results
def fragment_v3(configs: List[str], ping_results: Dict[str, Tuple[str, Optional[float]]] = None) -> List[Dict[str, Any]]:
    fragments = []
    for i, cfg in enumerate(configs):
        proto, parsed = parse_link_general(cfg)
        if not parsed:
            host = extract_host(cfg) or "0.0.0.0"
            parsed = {"protocol": "vless", "address": host, "port": 443, "user": "user", "params": {}, "remark": cfg, "raw": cfg}

        ping_val = None
        status = None
        if ping_results and cfg in ping_results:
            status, ping_val = ping_results[cfg]

        ping_str = f"{ping_val:.2f} ms" if isinstance(ping_val, (int, float)) else "NO REPLY"
        remark_base = parsed.get("remark") or f"Config {i+1}"
        remark_with_ping = f"{remark_base} | {ping_str} | {status or ''}"
        address = parsed.get("address", "0.0.0.0")
        port = parsed.get("port", 443)

        outbound = {
            "tag": "proxy",
            "protocol": parsed.get("protocol", "vless"),
            "settings": {"vnext": [{"address": address, "port": port, "users": [{"id": parsed.get("user", "user"), "encryption": "none", "flow": ""}]}]},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "sockopt": {"dialerProxy": "fragment"},
                "tlsSettings": {"serverName": address, "fingerprint": "chrome", "alpn": ["http/1.1"]},
                "wsSettings": {"path": "/", "headers": {"Host": address}}
            }
        }

        fragment = {
            "remarks": remark_with_ping,
            "log": {"loglevel": "warning"},
            "dns": {"servers": [{"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"},
                                {"address": "8.8.8.8", "domains": [f"full:{address}"], "skipFallback": True}],
                    "queryStrategy": "UseIP", "tag": "dns"},
            "inbounds": [
                {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},
                 "sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True},"tag":"socks-in"},
                {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
            ],
            "outbounds": [outbound, {"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],
            "routing": {"domainStrategy":"IPIfNonMatch","rules":[{"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},{"network":"tcp","outboundTag":"proxy","type":"field"}]}
        }
        fragments.append(fragment)
    return fragments

# Fragment V4: expects normalized parsed list with keys type/server/port/uuid/name/tls/network/password
def fragment_v4(parsed_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fragments = []
    for idx, cfg in enumerate(parsed_configs, 1):
        proto = cfg.get("type", "vless")
        server = cfg.get("server")
        port = cfg.get("port")
        uuid = cfg.get("uuid", "")
        name = cfg.get("name", f"proxy{idx}")
        tls = cfg.get("tls", False)
        network = cfg.get("network", "tcp")
        password = cfg.get("password", "")

        outbound = None
        if proto in ["vless", "vmess"]:
            outbound = {"tag":"proxy","protocol":proto,"settings":{"vnext":[{"address":server,"port":port,"users":[{"id":uuid,"encryption":"none"}]}]},"streamSettings":{"network":network,"security":"tls" if tls else "none"}}
        elif proto == "trojan":
            outbound = {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":server,"port":port,"password":password}]},"streamSettings":{"network":network,"security":"tls" if tls else "none"}}
        elif proto in ["ss","shadowsocks"]:
            outbound = {"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":server,"port":port,"password":password,"method":"aes-128-gcm"}]},"streamSettings":{"network":network,"security":"none"}}
        else:
            continue

        fragment = {"remarks": name, "log":{"loglevel":"warning"},
                    "inbounds":[{"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True},"tag":"socks-in"},
                                {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"},"tag":"dns-in"}],
                    "outbounds":[outbound,{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],
                    "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"network":"tcp","outboundTag":"proxy","type":"field"}]}}
        fragments.append(fragment)
    return fragments

# ---------------- Save helper ----------------
def save_fragment(fragment_list: List[Dict[str, Any]], default_name: str = "fragment"):
    fname = input(f"Enter output filename (default: {default_name}.json): ").strip() or default_name
    outpath = os.path.join(OUTPUT_FOLDER, fname + ".json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(fragment_list, f, ensure_ascii=False, indent=2)
    print(f"[green]✅ Saved {len(fragment_list)} items to {outpath}[/green]")

# ---------------- Menu loop (unchanged behavior) ----------------
def menu_loop(valid_raw_configs: List[str], parsed_list: List[Dict[str, Any]], ping_results: Dict[str, Tuple[str, Optional[float]]]):
    fragments_dict = {
        "1": ("Fragment V1 (parsed) — VLESS ws/tls", fragment_v1),
        "2": ("Fragment V2 (parsed) — multi-protocol", fragment_v2),
        "3": ("Fragment V3 (raw+ping) — parse_general", fragment_v3),
        "4": ("Fragment V4 (normalized parsed) — generic", fragment_v4)
    }
    while True:
        print("\n[bold cyan]Select fragment to generate:[/bold cyan]")
        for k, v in fragments_dict.items():
            print(f"{k}. {v[0]}")
        print("0. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "0":
            break
        if choice in fragments_dict:
            name, func = fragments_dict[choice]
            if choice == "1":
                output = func(parsed_list)
            elif choice == "2":
                output = func(parsed_list)
            elif choice == "3":
                output = func(valid_raw_configs, ping_results)
            elif choice == "4":
                normalized = []
                for p in parsed_list:
                    normalized.append({
                        "type": p.get("protocol", "vless"),
                        "server": p.get("address"),
                        "port": p.get("port"),
                        "uuid": p.get("id", p.get("user","")),
                        "name": p.get("remark", ""),
                        "tls": p.get("params", {}).get("security") == "tls",
                        "network": p.get("params", {}).get("type", "tcp"),
                        "password": p.get("params", {}).get("password", "")
                    })
                output = func(normalized)
            else:
                output = []
            if output is None:
                print("[red]❌ Function returned None or invalid output[/red]")
            else:
                save_fragment(output, default_name=name.replace(" ", "_"))
        else:
            print("[red]Invalid choice[/red]")

# ---------------- Main flow ----------------
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
        print("[red]No configs entered![/red]")
        return

    # ---------- Ping all configs concurrently with progress ----------
    print("[cyan]\nChecking ping for all configs (combined methods)...[/cyan]")
    results = []
    protocol_count = {}
    ping_results: Dict[str, Tuple[str, Optional[float]]] = {}

    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn()) as prog:
        task = prog.add_task("[cyan]Pinging hosts...", total=len(lines))
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(process_config_ping, cfg): cfg for cfg in lines}
            for fut in as_completed(futures):
                cfg, sub_ms, ping3_ms, status_sub, status_ping3 = fut.result()
                # choose best available avg: prefer ping3 then subprocess
                avg_ms = ping3_ms if ping3_ms is not None else sub_ms
                # decide overall status: if either method reported good/warn prefer that (logic: prefer best non-bad)
                overall_status = "bad"
                if status_ping3 in ("good", "warn"):
                    overall_status = status_ping3
                elif status_sub in ("good", "warn"):
                    overall_status = status_sub
                else:
                    overall_status = "bad"
                ping_results[cfg] = (overall_status, avg_ms)
                proto = extract_protocol(cfg)
                protocol_count[proto] = protocol_count.get(proto, 0) + 1
                results.append({
                    "config": cfg,
                    "protocol": proto,
                    "subprocess_ms": sub_ms,
                    "ping3_ms": ping3_ms,
                    "overall_status": overall_status,
                    "avg_ms": avg_ms
                })
                prog.update(task, advance=1)

    # ---------- Print summary table ----------
    table = Table(title="Configs Summary (Combined Ping)")
    table.add_column("Config")
    table.add_column("Protocol")
    table.add_column("Avg(ms)")
    table.add_column("Status")
    for r in results:
        avg_str = f"{r['avg_ms']:.2f}" if isinstance(r["avg_ms"], (int, float)) else "-"
        label = r["overall_status"].upper()
        table.add_row(r["config"], r["protocol"].upper(), avg_str, label)
    print(table)

    proto_table = Table(title="Protocol Counts")
    proto_table.add_column("Protocol")
    proto_table.add_column("Count")
    for proto, cnt in protocol_count.items():
        proto_table.add_row(proto.upper(), str(cnt))
    print(proto_table)

    # ---------- build parsed_list from valid configs (keep parsed entries) ----------
    valid_raw_configs = [cfg for cfg, (st,_) in ping_results.items() if st in ("good", "warn")]
    if not valid_raw_configs:
        print("[red]No live configs passed ping. Exiting.[/red]")
        return

    parsed_list = []
    for cfg in valid_raw_configs:
        parsed = parse_vless_link(cfg)
        if parsed:
            parsed_list.append(parsed)

    # ---------- menu ----------
    menu_loop(valid_raw_configs, parsed_list, ping_results)


if __name__ == "__main__":
    main()