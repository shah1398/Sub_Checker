#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import time
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from ping3 import ping
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn

# ==================== Settings ====================
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAX_THREADS = 20
PING3_COUNT = 3  # تعداد نمونه‌های ping3 برای میانگین

# ==================== Helpers (host/proto/ping) ====================
def extract_host(config: str):
    """Try to extract host from config string (supports user@host:port and other forms)."""
    if not config:
        return None
    m = re.search(r"@([^:/?#\s]+)", config)
    if m:
        return m.group(1)
    m2 = re.search(r"://([^:/?#\s]+)", config)
    return m2.group(1) if m2 else None

def extract_protocol(config: str):
    try:
        return config.split("://", 1)[0].lower()
    except:
        return "unknown"

# -------------------- Method 1: subprocess ping --------------------
def ping_subprocess(host: str):
    """Ping using system ping. Returns avg ms or None."""
    try:
        output = subprocess.check_output(
            ["ping", "-c", "3", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        # linux format: rtt min/avg/max/mdev = ...
        m = re.search(r"rtt min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)", output)
        if m:
            return float(m.group(1))
        # some systems use different wording; try fallback parse
        m2 = re.search(r"min/avg/max/.+ = [\d.]+/([\d.]+)", output)
        if m2:
            return float(m2.group(1))
        return None
    except Exception:
        return None

# -------------------- Method 2: ping3 --------------------
def ping_ping3(host: str, count: int = PING3_COUNT):
    """Ping using ping3, returns average ms or None."""
    results = []
    for _ in range(count):
        try:
            r = ping(host, timeout=1.2, unit="ms")
            if r is not None:
                results.append(r)
        except Exception:
            continue
    if results:
        return sum(results) / len(results)
    return None

def classify_ping(ms):
    """Return status key and label for printing."""
    if ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    try:
        m = float(ms)
    except:
        return "bad", "[bold red][BAD][/bold red]"
    if m < 150:
        return "good", "[bold green][GOOD][/bold green]"
    if m < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ==================== Pulse / parse_link (الگو) ====================
def parse_link(link: str):
    """
    Parse vless:// trojan:// ss:// style minimal parser.
    Returns (proto, parsed_dict) or (None, None).
    parsed_dict contains: protocol,address,port,user,params,remark,raw
    """
    link = (link or "").strip()
    if not link:
        return None, None
    if not any(link.startswith(p) for p in ["vless://", "trojan://", "ss://"]):
        return None, None
    try:
        proto = link.split("://", 1)[0]
        main_part = link.split("://", 1)[1]
        remark = ""
        if "#" in main_part:
            main_part, remark = main_part.split("#", 1)
        if "?" in main_part:
            addr_port, params = main_part.split("?", 1)
            query = urllib.parse.parse_qs(params)
        else:
            addr_port = main_part
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
        parsed = {
            "protocol": proto,
            "address": address,
            "port": int(port) if str(port).isdigit() else 443,
            "user": user,
            "id": user,  # convenience key 'id' used in fragments
            "params": {k: v[0] for k, v in query.items()},
            "remark": urllib.parse.unquote(remark) if remark else address,
            "raw": link
        }
        return proto, parsed
    except Exception:
        return None, None

# ==================== Ping + Stats (parallel) ====================
def process_all_pings(configs: list):
    """
    Given list of raw config lines: ping hosts in parallel and return:
      - valid_raws: list of raw config strings that were not ignored (we keep all, but record status)
      - ping_results: dict raw_config -> (status, avg_ms_or_none)
      - protocol_count: dict proto -> count
    """
    if not configs:
        return [], {}, {}

    protocol_count = {}
    ping_results = {}
    valid_raws = []

    def worker(cfg):
        host = extract_host(cfg)
        if not host:
            return cfg, None, None
        # try subprocess first, fallback to ping3
        sub = ping_subprocess(host)
        ping3 = ping_ping3(host)
        # prefer subprocess if available (both provided for info); take average of available
        ms_values = [x for x in (sub, ping3) if x is not None]
        avg = sum(ms_values) / len(ms_values) if ms_values else None
        status, _ = classify_ping(avg)
        return cfg, status, avg

    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn()) as prog:
        task = prog.add_task("[cyan]Pinging hosts...", total=len(configs))
        with ThreadPoolExecutor(max_workers=min(MAX_THREADS, max(2, len(configs)))) as ex:
            futures = {ex.submit(worker, cfg): cfg for cfg in configs}
            for fut in as_completed(futures):
                cfg, status, avg = fut.result()
                proto = extract_protocol(cfg)
                protocol_count[proto] = protocol_count.get(proto, 0) + 1
                ping_results[cfg] = (status, avg)
                if status in ("good", "warn"):
                    valid_raws.append(cfg)
                prog.update(task, advance=1)

    # print summary table
    table = Table(title="Ping Summary")
    table.add_column("Total")
    table.add_column("Valid (good|warn)")
    table.add_column("Good")
    table.add_column("Warn")
    table.add_column("Bad/None")
    good = sum(1 for s in ping_results.values() if s[0] == "good")
    warn = sum(1 for s in ping_results.values() if s[0] == "warn")
    bad = sum(1 for s in ping_results.values() if s[0] == "bad")
    table.add_row(str(len(configs)), str(len(valid_raws)), str(good), str(warn), str(bad))
    print(table)

    return valid_raws, ping_results, protocol_count

# ==================== Fragment builders (selected 5 optimized) ====================
# Each function expects input and returns list of fragments (dicts)

# ---- Fragment V1 (expects parsed dicts list) ----
def fragment_v1(parsed_configs):
    fragments = []
    for i, pc in enumerate(parsed_configs, start=1):
        # ensure keys
        addr = pc.get("address") or "0.0.0.0"
        port = pc.get("port") or 443
        params = pc.get("params", {}) or {}
        user_id = pc.get("id", pc.get("user", ""))
        network = params.get("type", "ws")
        security = params.get("security", "tls")
        server_name = params.get("sni") or params.get("host") or addr
        alpn = params.get("alpn", "http/1.1")
        alpn_list = alpn.split(",") if isinstance(alpn, str) else (alpn if isinstance(alpn, list) else ["http/1.1"])
        # build streamSettings
        stream = {"network": network, "security": security, "sockopt": {"dialerProxy": "fragment"}}
        if network == "ws":
            stream["wsSettings"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", addr)}}
        elif network == "grpc":
            svc = params.get("serviceName", "")
            stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}
        if security in ("tls", "xtls"):
            stream["tlsSettings"] = {"serverName": server_name, "fingerprint": params.get("fp", "chrome"), "alpn": alpn_list}
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": user_id, "encryption": params.get("encryption", "none"), "flow": params.get("flow", "")}]}]},
            "streamSettings": stream
        }
        fragment = {
            "remarks": pc.get("remark") or f"💦 {i} - VLESS",
            "log": {"loglevel": "warning"},
            "dns": {"servers": [{"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"}, {"address": "8.8.8.8", "domains": [f"full:{addr}"], "skipFallback": True}], "queryStrategy": "UseIP", "tag": "dns"},
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True}, "tag": "socks-in"},
                {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53}, "tag": "dns-in"}
            ],
            "outbounds": [outbound, {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"}, {"network": "tcp", "outboundTag": "proxy", "type": "field"}]}
        }
        fragments.append(fragment)
    return fragments

# ---- Fragment V2 (expects parsed dicts list; multi-protocol) ----
def fragment_v2(parsed_configs):
    fragments = []
    for i, pc in enumerate(parsed_configs, start=1):
        proto = (pc.get("protocol") or "vless").lower()
        addr = pc.get("address") or "0.0.0.0"
        port = pc.get("port") or 443
        params = pc.get("params") or {}
        uid = pc.get("id", pc.get("user", ""))
        name = pc.get("remark") or f"proxy{i}"
        tls_flag = params.get("security", "") == "tls"
        network = params.get("type", "tcp")
        if proto in ("vless", "vmess"):
            outbound = {"tag": "proxy", "protocol": proto, "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": uid, "encryption": "none"}]}]}, "streamSettings": {"network": network, "security": "tls" if tls_flag else "none", "sockopt": {"dialerProxy": "fragment"}}}
        elif proto == "trojan":
            outbound = {"tag": "proxy", "protocol": "trojan", "settings": {"servers": [{"address": addr, "port": port, "password": uid}]}, "streamSettings": {"network": network, "security": "tls" if tls_flag else "none", "sockopt": {"dialerProxy": "fragment"}}}
        elif proto in ("ss", "shadowsocks"):
            outbound = {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [{"address": addr, "port": port, "password": uid, "method": params.get("method", "aes-128-gcm")}]}, "streamSettings": {"network": network, "security": "none", "sockopt": {"dialerProxy": "fragment"}}}
        else:
            continue
        fragment = {"remarks": name, "log": {"loglevel": "warning"}, "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "tag": "socks-in"}, {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "port": 53, "network": "tcp,udp"}, "tag": "dns-in"}], "outbounds": [outbound, {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"network": "tcp", "outboundTag": "proxy", "type": "field"}]}}
        fragments.append(fragment)
    return fragments

# ---- Fragment V3 (expects raw config strings list + ping_results) ----
def fragment_v3(raw_configs, ping_results=None):
    fragments = []
    for i, raw in enumerate(raw_configs, start=1):
        proto, parsed = parse_link(raw)
        if parsed is None:
            # fallback minimal parsed
            host = extract_host(raw) or "0.0.0.0"
            parsed = {"protocol": "vless", "address": host, "port": 443, "id": "", "params": {}, "remark": raw, "raw": raw}
            proto = "vless"
        status_ping = ping_results.get(raw) if ping_results else None
        status, pingval = (status_ping[0], status_ping[1]) if status_ping else (None, None)
        ping_str = f"{pingval:.2f} ms" if isinstance(pingval, (int, float)) else "NO REPLY"
        remark = f"{parsed.get('remark','Config')} | {ping_str} | {status or ''}"
        addr = parsed.get("address", "0.0.0.0")
        port = parsed.get("port", 443)
        # Build a generic outbound (vless/trojan/ss guessed)
        outbound = {
            "tag": "proxy",
            "protocol": parsed.get("protocol", "vless"),
            "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": parsed.get("id", ""), "encryption": "none", "flow": ""}]}]},
            "streamSettings": {"network": "ws", "security": "tls", "sockopt": {"dialerProxy": "fragment"}, "tlsSettings": {"serverName": addr, "fingerprint": "chrome", "alpn": ["http/1.1"]}, "wsSettings": {"path": "/", "headers": {"Host": addr}}}
        }
        fragment = {"remarks": remark, "log": {"loglevel": "warning"}, "dns": {"servers": [{"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"}, {"address": "8.8.8.8", "domains": [f"full:{addr}"], "skipFallback": True}], "queryStrategy": "UseIP", "tag": "dns"}, "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True}, "tag": "socks-in"}], "outbounds": [outbound, {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"}, {"network": "tcp", "outboundTag": "proxy", "type": "field"}]}}
        fragments.append(fragment)
    return fragments

# ---- Fragment V4 (expects parsed dicts list; gRPC oriented) ----
def fragment_v4(parsed_configs):
    fragments = []
    for i, pc in enumerate(parsed_configs, start=1):
        addr = pc.get("address") or "0.0.0.0"
        port = pc.get("port") or 443
        uid = pc.get("id", "")
        svc = pc.get("params", {}).get("serviceName", "")
        outbound = {"tag": "proxy4", "protocol": "vless", "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": uid, "encryption": "none"}]}]}, "streamSettings": {"network": "grpc", "security": "tls", "sockopt": {"dialerProxy": "fragment"}, "grpcSettings": {"serviceName": svc}}}
        fragment = {"remarks": pc.get("remark") or f"🎯 {i} - VLESS-GRPC", "log": {"loglevel": "warning"}, "inbounds": [{"port": 10811, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "tag": "socks-in"}], "outbounds": [outbound, {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "120-220", "interval": "2-3"}, "domainStrategy": "UseIPv4v6"}}], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"inboundTag": ["socks-in"], "outboundTag": "proxy4", "type": "field"}]}}
        fragments.append(fragment)
    return fragments

# ---- Fragment V5 (expects parsed dicts list; XTLS example) ----
def fragment_v5(parsed_configs):
    fragments = []
    for i, pc in enumerate(parsed_configs, start=1):
        addr = pc.get("address") or "0.0.0.0"
        port = pc.get("port") or 443
        uid = pc.get("id", "")
        params = pc.get("params", {}) or {}
        stream = {"network": params.get("type", "ws"), "security": "xtls", "sockopt": {"dialerProxy": "fragment"}, "tlsSettings": {"serverName": params.get("sni", addr)}}
        outbound = {"tag": "proxy5", "protocol": "vless", "settings": {"vnext": [{"address": addr, "port": port, "users": [{"id": uid, "encryption": "none"}]}]}, "streamSettings": stream}
        fragment = {"remarks": pc.get("remark") or f"🔥 {i} - VLESS-XTLS", "log": {"loglevel": "warning"}, "inbounds": [{"port": 10812, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "tag": "socks-in"}], "outbounds": [outbound, {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}}], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"inboundTag": ["socks-in"], "outboundTag": "proxy5", "type": "field"}]}}
        fragments.append(fragment)
    return fragments

# ==================== Save helper ====================
def save_fragment_list(fragment_list, default_name="fragment_output"):
    fname = input(f"Enter filename (default: {default_name}.json): ").strip() or default_name
    path = os.path.join(OUTPUT_FOLDER, fname + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fragment_list, f, ensure_ascii=False, indent=2)
    print(f"[green]✅ Saved {len(fragment_list)} fragments to {path}[/green]")

# ==================== Interactive menu ====================
def menu_loop(valid_raws, ping_results, parsed_list):
    """
    valid_raws : list of raw config strings that passed ping (good|warn)
    ping_results : dict raw -> (status, avg_ms)
    parsed_list  : list of parsed dicts for those configs (only where parse_link succeeded)
    We'll let user choose which fragment builder to run and pass appropriate inputs.
    """
    builders = {
        "1": ("Fragment V1 (parsed -> VLESS-like)", fragment_v1, "parsed"),
        "2": ("Fragment V2 (parsed -> multi-proto)", fragment_v2, "parsed"),
        "3": ("Fragment V3 (raw + ping -> generic)", fragment_v3, "raw"),
        "4": ("Fragment V4 (parsed -> gRPC)", fragment_v4, "parsed"),
        "5": ("Fragment V5 (parsed -> XTLS)", fragment_v5, "parsed")
    }
    while True:
        print("\n[cyan]Choose fragment type to generate:[/cyan]")
        for k, v in builders.items():
            print(f"{k}) {v[0]}")
        print("0) Exit")
        ch = input("Choice: ").strip()
        if ch == "0":
            break
        if ch not in builders:
            print("[red]Invalid choice[/red]"); continue
        name, func, kind = builders[ch]
        if kind == "parsed":
            # Ensure we have parsed_list for all valid_raws; if not, try to parse and include fallback parsed
            if not parsed_list:
                # try to build parsed_list from valid_raws
                tmp = []
                for raw in valid_raws:
                    _, p = parse_link(raw)
                    if p:
                        tmp.append(p)
                parsed_input = tmp
            else:
                parsed_input = parsed_list
            output = func(parsed_input)
        else:  # raw
            output = func(valid_raws, ping_results)
        if not output:
            print("[red]No fragments produced (function returned empty).[/red]")
            continue
        save_fragment_list(output, default_name=name.replace(" ", "_"))
        print("[green]Done.[/green]")

# ==================== MAIN ====================
def main():
    print("[cyan]Paste your configs line by line (Ctrl+D when done):[/cyan]")
    lines = []
    while True:
        try:
            ln = input()
            if ln and ln.strip():
                lines.append(ln.strip())
        except EOFError:
            break
    if not lines:
        print("[red]No input provided. Exiting.[/red]")
        return

    # ping all
    valid_raws, ping_results, proto_count = process_all_pings(lines)

    # build parsed_list for parsed-based fragment functions
    parsed_list = []
    for raw in valid_raws:
        _, parsed = parse_link(raw)
        if parsed:
            parsed_list.append(parsed)
        else:
            # try parse even if not parsed (we keep minimal fallback)
            # skipping if can't parse
            continue

    # show protocol counts
    pt = Table(title="Protocol Counts")
    pt.add_column("Protocol"); pt.add_column("Count")
    for k, v in proto_count.items():
        pt.add_row(k.upper(), str(v))
    print(pt)

    # menu
    menu_loop(valid_raws, ping_results, parsed_list)

if __name__ == "__main__":
    main()