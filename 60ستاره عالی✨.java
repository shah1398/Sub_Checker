#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import requests
import json
import random
import base64
from urllib.parse import parse_qs, unquote
from rich import print

# ---------------- constants & paths ----------------
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

FOLDER = "/storage/emulated/0/Download/Akbar98"
os.makedirs(FOLDER, exist_ok=True)

protocols = ["vmess://", "vless://", "trojan://", "ss://"]

# ---------------- Helpers ----------------
def safe_b64_decode(s: str):
    if not s:
        return None
    s = s.strip()
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        return base64.b64decode(s).decode(errors="ignore")
    except Exception:
        return None

def strip_protocol(link: str) -> str:
    if "://" in link:
        return link.split("://", 1)[1]
    return link

def extract_host(config):
    match = re.search(r"@([^:/?#]+)", config)
    return match.group(1) if match else None

def ping_host(host):
    try:
        output = subprocess.check_output(
            ["ping", "-c", "3", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None
    except Exception:
        return None

def classify_ping(ping):
    if ping is None:
        return "red", f"{RED}✖ BAD{RESET}"
    elif ping < 150:
        return "green", f"{GREEN}✔ GOOD{RESET}"
    elif ping < 300:
        return "yellow", f"{YELLOW}⚠ WARN{RESET}"
    else:
        return "red", f"{RED}✖ BAD{RESET}"

def fetch_sub_link(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        content = r.text
        content = ''.join([c for c in content if ord(c) < 128])
        return content
    except Exception as e:
        print(f"{RED}❌ Failed to fetch: {url}\nError: {e}{RESET}")
        return None

def parse_configs(raw_data):
    lines = raw_data.splitlines()
    configs = [line.strip() for line in lines if line.strip()]
    return configs

def categorize_configs(configs):
    vless, trojan, ss, others = [], [], [], []
    for cfg in configs:
        lower = cfg.lower()
        if "vless://" in lower:
            vless.append(cfg)
        elif "trojan://" in lower:
            trojan.append(cfg)
        elif "ss://" in lower:
            ss.append(cfg)
        else:
            others.append(cfg)
    return vless, trojan, ss, others

# ---------------- file saving ----------------
def save_to_file(filename, data):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        for d in data:
            f.write(d + "\n")
    print(f"{GREEN}✅ Saved file: {os.path.abspath(filename)}{RESET}")

def save_json(filename, data):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"{GREEN}✅ Saved JSON: {os.path.abspath(filename)}{RESET}")

# ---------------- Parsers (vless/trojan/ss) ----------------
def parse_vless(link: str):
    try:
        rest = link.split("://", 1)[1]
        remark = ""
        if "#" in rest:
            rest, remark = rest.split("#", 1)
            remark = unquote(remark)
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
            "port": int(port) if str(port).isdigit() else 443,
            "user": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": remark or link
        }
    except Exception:
        return None

def parse_trojan(link: str):
    try:
        rest = link.split("://", 1)[1]
        remark = ""
        if "#" in rest:
            rest, remark = rest.split("#", 1)
            remark = unquote(remark)
        if "?" in rest:
            addr_port, params = rest.split("?", 1)
            query = parse_qs(params)
        else:
            addr_port = rest
            query = {}
        if "@" in addr_port:
            passwd, host_port = addr_port.split("@", 1)
        else:
            passwd = ""
            host_port = addr_port
        if ":" in host_port:
            address, port = host_port.split(":", 1)
        else:
            address = host_port
            port = "443"
        return {
            "protocol": "trojan",
            "raw": link,
            "address": address,
            "port": int(port) if str(port).isdigit() else 443,
            "user": passwd,
            "params": {k: v[0] for k, v in query.items()},
            "remark": remark or link
        }
    except Exception:
        return None

def parse_ss(link: str):
    try:
        main = link.split("://", 1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#", 1)
        remark = unquote(remark)
        if "@" in main and ":" in main.split("@", 1)[1]:
            method_pass, host_port = main.split("@", 1)
            if ":" in method_pass:
                method, password = method_pass.split(":", 1)
            else:
                method, password = method_pass, ""
            if ":" in host_port:
                address, port = host_port.split(":", 1)
            else:
                address, port = host_port, "443"
            return {
                "protocol": "ss",
                "raw": link,
                "address": address,
                "port": int(port) if str(port).isdigit() else 443,
                "user": password,
                "method": method,
                "params": {},
                "remark": remark or link
            }
        else:
            decoded = safe_b64_decode(main)
            if decoded and "@" in decoded:
                method_pass, host_port = decoded.split("@", 1)
                if ":" in method_pass:
                    method, password = method_pass.split(":", 1)
                else:
                    method, password = method_pass, ""
                if ":" in host_port:
                    address, port = host_port.split(":", 1)
                else:
                    address, port = host_port, "443"
                return {
                    "protocol": "ss",
                    "raw": link,
                    "address": address,
                    "port": int(port) if str(port).isdigit() else 443,
                    "user": password,
                    "method": method,
                    "params": {},
                    "remark": remark or link
                }
    except Exception:
        return None
    return None

def parse_config(conf: str):
    conf = conf.strip()
    if conf.startswith("vless://"): return parse_vless(conf)
    if conf.startswith("trojan://"): return parse_trojan(conf)
    if conf.startswith("ss://"): return parse_ss(conf)
    return None
# ---------------- Fragment builder ----------------
MAX_COMBO = 80  # سقف ترکیب‌ها

def build_fragment(parsed, ping_results=None):
    if not parsed:
        return None
    proto = parsed.get("protocol")
    address = parsed.get("address")
    port = parsed.get("port")
    remark = parsed.get("remark") or f"{proto} fragment"
    raw = parsed.get("raw", "")
    params = parsed.get("params", {})
    status = None
    ping = None
    if ping_results and raw in ping_results:
        status, ping = ping_results[raw]
    ping_str = f"{ping:.2f} ms" if isinstance(ping, (int, float)) else "NO REPLY"
    remark_with_ping = f"{remark} | {ping_str} | {status.upper() if status else ''}"

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

    outbound = None
    if proto == "vless":
        user_id = parsed.get("user","")
        network = params.get("type","ws")
        security = params.get("security","tls")
        sni = params.get("sni", params.get("host", address))
        fp = params.get("fp","chrome")
        alpn = params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
        path = params.get("path","/")
        host_header = params.get("host", address)
        stream = {"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
        if network == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
        elif network == "grpc":
            svc = params.get("serviceName","")
            stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}
        if security in ["tls","xtls"]:
            stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}
        outbound = {"tag":"proxy","protocol":"vless",
                   "settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user_id,"encryption":params.get("encryption","none"),"flow":params.get("flow","")}]}]},
                   "streamSettings": stream}
    elif proto == "trojan":
        password = parsed.get("user","")
        network = params.get("type","ws")
        security = params.get("security","tls")
        sni = params.get("sni", params.get("host", address))
        fp = params.get("fp","chrome")
        alpn = params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
        path = params.get("path","/")
        host_header = params.get("host", address)
        stream = {"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
        if network == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
        elif network == "grpc":
            svc = params.get("serviceName","")
            stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}
        if security in ["tls","xtls"]:
            stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "alpn": alpn}
        outbound = {"tag":"proxy","protocol":"trojan",
                   "settings":{"servers":[{"address":address,"port":port,"password":password,"flow":params.get("flow","")}]},
                   "streamSettings": stream}
    elif proto == "ss":
        method = parsed.get("method","aes-128-gcm")
        password = parsed.get("user","")
        outbound = {"tag":"proxy","protocol":"shadowsocks",
                   "settings":{"servers":[{"address":address,"port":port,"method":method,"password":password}]},
                   "streamSettings":{"network":"tcp","security":"none","sockopt":{"dialerProxy":"fragment"}}}
    else:
        return None

    return {
        "remarks": remark_with_ping,
        "log": {"loglevel":"warning"},
        "inbounds": inbounds_block,
        "outbounds": [outbound, {"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],
        "routing": routing_block
    }

# ---------------- Combo generators ----------------
def generate_combo2(configs: list, cap: int = MAX_COMBO) -> list:
    n = len(configs)
    if n < 2:
        return []
    indices = [(i,j) for i in range(n) for j in range(i+1,n)]
    random.shuffle(indices)
    combos = []
    seen = set()
    for i,j in indices:
        combo = f"{configs[i]}+{configs[j]}"
        if combo not in seen:
            combos.append(combo)
            seen.add(combo)
        if len(combos) >= cap:
            break
    return combos

def generate_combo3(configs: list, cap: int = MAX_COMBO) -> list:
    n = len(configs)
    if n < 3:
        return []
    cands = []
    for a in range(n):
        for b in range(a+1, n):
            for c in range(b+1, n):
                cands.append((a,b,c))
                if len(cands) >= cap*8:
                    break
            if len(cands) >= cap*8:
                break
        if len(cands) >= cap*8:
            break
    random.shuffle(cands)
    combos = []
    seen = set()
    for i,j,k in cands:
        A = configs[i]; B = configs[j]; C = configs[k]
        tail = strip_protocol(C)
        combo = f"{A}+{B}+ss://{tail}"
        if combo in seen:
            continue
        seen.add(combo)
        combos.append(combo)
        if len(combos) >= cap:
            break
    return combos

# ---------------- helper for 2combo extraction ----------------
def generate_2combo_from_3combo_file(file_path):
    combos2 = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split('+')
                if len(parts) >= 2:
                    combos2.append(parts[0] + "+" + parts[1])
    except Exception:
        pass
    return combos2

def save_combo_to_file(combo_list, filename, folder):
    path = os.path.join(folder, filename)
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(combo_list))
    print(f"{GREEN}✅ Saved {len(combo_list)} combos to: {os.path.abspath(path)}{RESET}")

# ---------------- Main (continued) ----------------
def main():
    all_configs = []

    print("[cyan]Choose input method:[/cyan]")
    print("1) Manual input (Ctrl+D to finish)")
    print("2) Fetch from subscription URL")
    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        print("[cyan]Paste your configs line by line. Press Ctrl+D to finish:[/cyan]")
        try:
            while True:
                line = input()
                if line.strip():
                    all_configs.append(line.strip())
        except EOFError:
            pass
    elif choice == "2":
        while True:
            url = input("Enter subscription URL: ").strip()
            r = fetch_sub_link(url)
            if r:
                all_configs.extend(parse_configs(r))
                print(f"{GREEN}✅ Fetched {len(parse_configs(r))} configs{RESET}")
            more = input("Add another link? (y/n): ").strip().lower()
            if more != "y":
                break
    else:
        print("Invalid choice.")
        return

    # dedupe while preserving order
    seen_tmp = set()
    unique_configs = []
    for c in all_configs:
        if c not in seen_tmp:
            unique_configs.append(c)
            seen_tmp.add(c)
    all_configs = unique_configs

    vless, trojan, ss, others = categorize_configs(all_configs)

    print(f"\nTotal configs: {len(all_configs)}")
    print(f"VLESS: {len(vless)}")
    print(f"TROJAN: {len(trojan)}")
    print(f"SHADOWSOCKS: {len(ss)}")
    print(f"Others: {len(others)}")

    green, yellow, red = [], [], []
    ping_results = {}
    parsed_list = []

    print("\nPerforming ping checks...")
    for config in all_configs:
        host = extract_host(config)
        if not host:
            print(f"{RED}[INVALID] {config}{RESET}")
            continue
        ping_val = ping_host(host)
        status, label = classify_ping(ping_val)
        print(f"{label} {host} - {ping_val if ping_val else 'NO REPLY'}ms")
        if status == "green":
            green.append(config)
        elif status == "yellow":
            yellow.append(config)
        else:
            red.append(config)
        ping_results[config] = (status, ping_val)

        parsed = parse_config(config)
        if parsed:
            parsed_list.append(parsed)

    while True:
        print("\nChoose output format:")
        print(" 0) Exit")
        print(" 1) VLESS only")
        print(" 2) TROJAN only")
        print(" 3) SHADOWSOCKS only")
        print(" 4) All configs")
        print(f" 5) Combo (VLESS + TROJAN) - Max {MAX_COMBO}")
        print(f" 6) Combo (VLESS + TROJAN + SS) - Max {MAX_COMBO}")
        print(" 7) Green only")
        print(" 8) Green + Yellow")
        print(" 9) Save all configs (custom name)")
        print("10) Save all as JSON")
        print("11) YAML for Clash Meta")
        print("12) Fragmented JSON (all green)")
        print("13) Fragment")
        print("14) Raw Parsed JSON (all configs)")

        option = input("Enter choice number [0-14]: ").strip()

        if option == "0":
            print("Exiting...")
            break

        elif option == "1":
            name = input("File name: ").strip() or "output_vless"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), vless)

        elif option == "2":
            name = input("File name: ").strip() or "output_trojan"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), trojan)

        elif option == "3":
            name = input("File name: ").strip() or "output_ss"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), ss)

        elif option == "4":
            name = input("File name: ").strip() or "output_all"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), all_configs)

        elif option == "5":
            combo = vless + trojan
            combos2 = generate_combo2(combo, cap=MAX_COMBO)
            name = input("File name for 2-combo (txt): ").strip() or "combo_vless_trojan"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), combos2)

        elif option == "6":
            combo_all = vless + trojan + ss
            combos3 = generate_combo3(combo_all, cap=MAX_COMBO)
            name = input("File name for 3-combo (txt): ").strip() or "combo_vless_trojan_ss"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), combos3)

        elif option == "7":
            name = input("File name: ").strip() or "green_ping"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), green)

        elif option == "8":
            name = input("File name: ").strip() or "green_yellow_ping"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), green + yellow)

        elif option == "9":
            name = input("Custom filename: ").strip() or "all_configs"
            if not name.endswith(".txt"): name += ".txt"
            save_to_file(os.path.join(FOLDER, name), all_configs)

        elif option == "10":
            name = input("JSON filename: ").strip() or "output_all"
            if not name.endswith(".json"): name += ".json"
            data = [parse_config(cfg) for cfg in all_configs if parse_config(cfg)]
            save_json(os.path.join(FOLDER, name), data)

        elif option == "11":
            file_name = input("YAML file name: ").strip() or "clash_config"
            if not file_name.endswith(".yaml"): file_name += ".yaml"
            yaml_data = {"proxies": all_configs, "name": "Clash Meta Config", "type": "mixed"}
            save_yaml(os.path.join(FOLDER, file_name), yaml_data)
            link = f"https://mago81.ahsan-tepo1383online.workers.dev/clash/akbar98/{quote(file_name)}"
            print(f"[bold green]YAML saved and link ready:[/bold green] {link}")

        elif option == "12":
            fragments = []
            for cfg in green:
                parsed = parse_config(cfg)
                if parsed:
                    frag = build_fragment(parsed, ping_results)
                    if frag:
                        fragments.append(frag)
            name = input("File name for fragmented JSON (without ext): ").strip() or "fragmented_green"
            if not name.endswith(".json"): name += ".json"
            save_json(os.path.join(FOLDER, name), fragments)

        elif option == "13":
            fragments = []
            for parsed in parsed_list:
                frag = build_fragment(parsed, ping_results)
                if frag:
                    fragments.append(frag)
            name = input("File name for fragment JSON (without ext): ").strip() or "fragment_all"
            if not name.endswith(".json"): name += ".json"
            save_json(os.path.join(FOLDER, name), fragments)

        elif option == "14":
            data = [parse_config(cfg) for cfg in all_configs if parse_config(cfg)]
            name = input("File name for raw parsed JSON (without ext): ").strip() or "raw_parsed"
            if not name.endswith(".json"): name += ".json"
            save_json(os.path.join(FOLDER, name), data)

        else:
            print(f"{RED}Invalid option.{RESET}")

if __name__ == "__main__":
    main()
