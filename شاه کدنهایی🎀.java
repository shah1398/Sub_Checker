#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ==================== Imports ====================
import os
import re
import subprocess
import time
import json
import urllib.parse
from urllib.parse import parse_qs, unquote
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn

# ==================== Settings ====================
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAX_THREADS = 20
PING3_COUNT = 3  # تعداد پینگ3 برای میانگین

PROTOCOLS = ["vless://", "vmess://", "trojan://", "ss://", "grpc://", "vmess://"]

# ==================== Helpers (Pulse / Parse) ====================
def parse_link(link):
    """
    Pulse parser for vless:// trojan:// ss://
    returns (proto, parsed_dict) or (None, None)
    parsed_dict includes address, port, user/id, params dict, remark, raw
    """
    link = link.strip()
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
            "id": user,  # alias
            "params": {k: v[0] for k, v in query.items()},
            "remark": urllib.parse.unquote(remark) or link,
            "raw": link
        }
        return proto, parsed
    except Exception:
        return None, None

def parse_vless_link(link):
    """Lightweight specific vless parser returning parsed dict or None"""
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
            "protocol":"vless",
            "address":address,
            "port":int(port) if str(port).isdigit() else 443,
            "id":user_id,
            "user":user_id,
            "params":{k:v[0] for k,v in query.items()},
            "remark":remark or link,
            "raw": link
        }
    except:
        return None

# ==================== Ping Core (unchanged logic & coloring) ====================
def extract_host(config: str):
    m = re.search(r"@([^:/?#\s]+)", config)
    if m:
        return m.group(1)
    m = re.search(r"://([^:/?#\s]+)", config)
    return m.group(1) if m else None

def extract_protocol(config: str):
    proto = config.split("://")[0].lower()
    return proto

def ping_subprocess(host: str):
    try:
        output = subprocess.check_output(
            ["ping", "-c", "3", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode()
        match = re.search(r"rtt min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None
    except Exception:
        return None

def ping_ping3(host: str, count: int = PING3_COUNT):
    results = []
    for _ in range(count):
        try:
            result = ping(host, timeout=1, unit="ms")
            if result is not None:
                results.append(result)
        except Exception:
            continue
    if results:
        return sum(results) / len(results)
    return None

def classify_ping(avg_ms):
    if avg_ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    try:
        av = float(avg_ms)
    except:
        return "bad", "[bold red][BAD][/bold red]"
    if av < 150:
        return "good", "[bold green][GOOD][/bold green]"
    if av < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ==================== Prompt input & run pings ====================
def collect_and_ping():
    print("[cyan]Enter your configs line by line (any protocol). Ctrl+D when done:[/cyan]")
    configs = []
    while True:
        try:
            line = input()
            if line.strip():
                configs.append(line.strip())
        except EOFError:
            break
    if not configs:
        print("[bold red]No configs entered![/bold red]")
        return None, None, None

    protocol_count = {}
    for cfg in configs:
        proto = extract_protocol(cfg)
        protocol_count[proto] = 0

    results = []

    def process_config(cfg: str):
        host = extract_host(cfg)
        if not host:
            return cfg, None, None, None, None
        sub_ms = ping_subprocess(host)
        ping3_ms = ping_ping3(host, count=PING3_COUNT)
        status_sub, _ = classify_ping(sub_ms)
        status_ping3, _ = classify_ping(ping3_ms)
        return cfg, sub_ms, ping3_ms, status_sub, status_ping3

    start_time = time.time()
    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("[cyan]Pinging hosts...", total=len(configs))
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_cfg = {executor.submit(process_config, cfg): cfg for cfg in configs}
            for future in as_completed(future_to_cfg):
                cfg, sub_ms, ping3_ms, status_sub, status_ping3 = future.result()
                proto = extract_protocol(cfg)
                if status_sub is None and status_ping3 is None:
                    print(f"[bold yellow]Ignored (invalid):[/bold yellow] {cfg}")
                    progress.update(task, advance=1)
                    continue
                protocol_count[proto] = protocol_count.get(proto, 0) + 1
                results.append({
                    "config": cfg,
                    "protocol": proto,
                    "subprocess_ms": sub_ms,
                    "ping3_ms": ping3_ms,
                    "subprocess_status": status_sub,
                    "ping3_status": status_ping3
                })
                progress.update(task, advance=1)

    table = Table(title="Configs Summary (Combined Ping)")
    table.add_column("Config")
    table.add_column("Protocol")
    table.add_column("SubProc(ms)")
    table.add_column("SubProc Status")
    table.add_column("Ping3(ms)")
    table.add_column("Ping3 Status")

    for r in results:
        table.add_row(
            r["config"],
            r["protocol"].upper(),
            str(r["subprocess_ms"]) if r["subprocess_ms"] is not None else "-",
            r["subprocess_status"].upper() if r["subprocess_status"] else "-",
            str(r["ping3_ms"]) if r["ping3_ms"] is not None else "-",
            r["ping3_status"].upper() if r["ping3_status"] else "-"
        )

    proto_table = Table(title="Protocol Counts")
    proto_table.add_column("Protocol")
    proto_table.add_column("Count")
    for proto, count in protocol_count.items():
        proto_table.add_row(proto.upper(), str(count))
    print(proto_table)

    elapsed = time.time() - start_time
    print(f"[cyan]Elapsed time: {elapsed:.2f} seconds[/cyan]")

    return configs, results, protocol_count
# ==================== Fragment functions (اصلاح شده طبق اهداف و کدمادر) ====================
def fragment_v2(parsed_configs):
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

def build_fragment_list_from_vless(parsed_configs):
    fragments = []
    for pc in parsed_configs:
        address = pc.get("address","0.0.0.0")
        port = pc.get("port",443)
        proto = pc.get("protocol","vless")
        remark = pc.get("remark",f"{proto}_{address}")

        dns_block = {
            "servers":[
                {"address":"https://8.8.8.8/dns-query","tag":"remote-dns"},
                {"address":"8.8.8.8","domains":[f"full:{address}"],"skipFallback":True}
            ],
            "queryStrategy":"UseIP",
            "tag":"dns"
        }

        inbounds_block = [
            {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},
             "sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True},"tag":"socks-in"},
            {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
        ]

        routing_block = {
            "domainStrategy":"IPIfNonMatch",
            "rules":[
                {"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},
                {"network":"tcp","outboundTag":"proxy","type":"field"}
            ]
        }

        params = pc.get("params",{})
        user_id = pc.get("user", pc.get("id",""))
        network = params.get("type","ws")
        security = params.get("security","tls")
        sni = params.get("sni",address)
        path = params.get("path","/")
        fp = params.get("fp","chrome")
        alpn = params.get("alpn","http/1.1").split(",") if params.get("alpn") else ["http/1.1"]
        host_header = params.get("host",address)

        outbound = {
            "tag":"proxy",
            "protocol":"vless",
            "settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user_id,"encryption":params.get("encryption","none"),"flow":params.get("flow","")}]}]},
            "streamSettings":{"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"},
                              "tlsSettings":{"serverName":sni,"fingerprint":fp,"alpn":alpn},
                              "wsSettings":{"path":path,"headers":{"Host":host_header}}}
        }

        fragment = {"remarks":remark,"log":{"loglevel":"warning"},"dns":dns_block,"inbounds":inbounds_block,"outbounds":[outbound,{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],"routing":routing_block}
        fragments.append(fragment)
    return fragments

# ==================== Save helpers ====================
def ask_and_save_text(lines_list, default_name):
    fname = input(f"Enter filename (default: {default_name}): ").strip() or default_name
    if not fname.endswith(".txt"):
        fname = fname + ".txt"
    path = os.path.join(OUTPUT_FOLDER, fname)
    with open(path, "w", encoding="utf-8") as f:
        for l in lines_list:
            f.write(l + "\n")
    print(f"[green]Saved {len(lines_list)} items -> {path}[/green]")

def ask_and_save_json(obj, default_name):
    fname = input(f"Enter filename (default: {default_name}): ").strip() or default_name
    if not fname.endswith(".json"):
        fname = fname + ".json"
    path = os.path.join(OUTPUT_FOLDER, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
# ==================== Main menu & wiring ====================
def main():
    # collect and ping
    collected = collect_and_ping()
    if collected is None:
        return
    configs_raw, ping_results, protocol_count = collected

    # Build parsed_list for vless-style parsed dicts (we'll use parse_vless_link)
    parsed_vless = []
    for cfg in configs_raw:
        parsed = parse_vless_link(cfg)
        if parsed:
            parsed_vless.append(parsed)

    # Also build generic parsed dicts via parse_link (pulse) for functions expecting parsed dicts
    parsed_generic = []
    for cfg in configs_raw:
        proto, p = parse_link(cfg)
        if p:
            parsed_generic.append(p)

    # menu
    while True:
        print("\n[cyan]Choose output (0 to exit):[/cyan]")
        print("1) VLESS (raw links)")
        print("2) VMess (raw links)")
        print("3) Shadowsocks (raw links)")
        print("4) Trojan (raw links)")
        print("5) Fragment V2 (multi-protocol)  <-- new")
        print("6) Fragmented VLESS JSON (was 8)")
        print("0) Exit")
        choice = input("Select an option: ").strip()
        if choice == "0":
            print("[cyan]Exiting.[/cyan]")
            break
        if choice == "1":
            lst = [c for c in configs_raw if c.startswith("vless://")]
            ask_and_save_text(lst, "vless")
        elif choice == "2":
            lst = [c for c in configs_raw if c.startswith("vmess://")]
            ask_and_save_text(lst, "vmess")
        elif choice == "3":
            lst = [c for c in configs_raw if c.startswith("ss://")]
            ask_and_save_text(lst, "shadowsocks")
        elif choice == "4":
            lst = [c for c in configs_raw if c.startswith("trojan://")]
            ask_and_save_text(lst, "trojan")
        elif choice == "5":
            # fragment_v2 expects parsed_configs list (dicts). We'll pass parsed_generic where possible.
            cfgs = parsed_generic if parsed_generic else parsed_vless
            if not cfgs:
                print("[yellow]No parsed configs available to build fragments.[/yellow]")
                continue
            frags = fragment_v2(cfgs)
            ask_and_save_json(frags, "fragment_v2")
        elif choice == "6":
            if not parsed_vless:
                print("[yellow]No VLESS parsed configs available to build fragmented JSON.[/yellow]")
                continue
            frags = build_fragment_list_from_vless(parsed_vless)
            ask_and_save_json(frags, "fragment_vless_list")
        else:
            print("[red]Invalid choice[/red]")

if __name__ == "__main__":
    main()

