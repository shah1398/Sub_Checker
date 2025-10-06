#!/usr/bin/env python3
import os
import re
import subprocess
import requests
import json
import base64
import random
import urllib.parse
from urllib.parse import parse_qs, unquote
from rich import print
from rich.prompt import Prompt

# ------------------ ثابت مسیر خروجی ------------------
SAVE_DIR = "/storage/emulated/0/Download/Akbar98"
os.makedirs(SAVE_DIR, exist_ok=True)

protocols = ["vmess://", "vless://", "trojan://", "ss://"]

# ------------------ Helpers ------------------
def safe_b64_decode(s: str):
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

def save_to_file_list(folder, filename, data_list):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        for item in data_list:
            f.write(item + "\n")
    print(f"[bold green]✅ Saved to {path}[/bold green]")
    return path

def save_json_file(folder, filename, data):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[bold green]✅ Saved JSON to {path}[/bold green]")
    return path

# ------------------ استخراج هاست و پینگ ------------------
def extract_host(config):
    match = re.search(r"@([^:/?#\s]+)", config)
    if match:
        return match.group(1)
    m2 = re.search(r"://([^:/?#\s]+)", config)
    return m2.group(1) if m2 else None

def ping_host(host, count=3):
    try:
        output = subprocess.check_output(
            ["ping", "-c", str(count), "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        if m:
            return float(m.group(1))
        m2 = re.search(r"round-trip.* = [\d.]+/([\d.]+)", output)
        if m2:
            return float(m2.group(1))
        return None
    except Exception:
        return None

def classify_ping(ping):
    if ping is None:
        return "bad", "[bold red][BAD][/bold red]"
    elif ping < 150:
        return "good", "[bold green][GOOD][/bold green]"
    elif ping < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    else:
        return "bad", "[bold red][BAD][/bold red]"

# ------------------ Parsers (exact from your snippets) ------------------
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
            "port": int(port) if port.isdigit() else 443,
            "user": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": unquote(remark)
        }
    except:
        return None

def parse_trojan(link: str):
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
            "port": int(port) if port.isdigit() else 443,
            "user": passwd,
            "params": {k: v[0] for k, v in query.items()},
            "remark": unquote(remark)
        }
    except:
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
                "port": int(port) if port.isdigit() else 443,
                "user": password,
                "method": method,
                "params": {},
                "remark": remark
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
                    "port": int(port) if port.isdigit() else 443,
                    "user": password,
                    "method": method,
                    "params": {},
                    "remark": remark
                }
    except:
        return None
    return None

def parse_vmess(link: str):
    try:
        rest = link.split("://", 1)[1]
        remark = ""
        if "#" in rest:
            rest, remark = rest.split("#", 1)
        decoded = safe_b64_decode(rest)
        if not decoded:
            return None
        try:
            js = json.loads(decoded)
            address = js.get("add") or js.get("address","")
            port = int(js.get("port") or js.get("ps") or 443)
            user = js.get("id","")
            network = js.get("net","tcp")
            params = {"network": network}
            return {"protocol":"vmess","raw":link,"address":address,"port":port,"user":user,"params":params,"remark":unquote(remark)}
        except:
            parts = decoded.split(":")
            if len(parts) >= 4:
                address = parts[0]
                port = int(parts[1]) if parts[1].isdigit() else 443
                user = parts[2]
                network = parts[3]
                return {"protocol":"vmess","raw":link,"address":address,"port":port,"user":user,"params":{"network":network},"remark":unquote(remark)}
    except:
        return None
    return None

def parse_config(conf: str):
    conf = conf.strip()
    if conf.startswith("vless://"):
        return parse_vless(conf)
    if conf.startswith("trojan://"):
        return parse_trojan(conf)
    if conf.startswith("ss://"):
        return parse_ss(conf)
    if conf.startswith("vmess://"):
        return parse_vmess(conf)
    return None

# ------------------ Fragment builder (exact as you provided) ------------------
def build_fragment(parsed, ping_results=None):
    if not parsed:
        return None
    proto = parsed.get("protocol")
    address = parsed.get("address")
    port = parsed.get("port")
    remark = parsed.get("remark") or f"{proto} fragment"
    raw = parsed.get("raw","")
    params = parsed.get("params", {})
    status = None
    ping = None
    if ping_results and raw in ping_results:
        status, ping = ping_results[raw]
    ping_str = f"{ping:.2f} ms" if isinstance(ping,(int,float)) else "NO REPLY"
    remark_with_ping = f"{remark} | {ping_str} | {status.upper() if status else ''}"

    inbounds_block = [
        {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True},"tag":"socks-in"},
        {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"},"tag":"dns-in"}
    ]
    routing_block = {"domainStrategy":"IPIfNonMatch","rules":[{"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},{"network":"tcp","outboundTag":"proxy","type":"field"}]}

    outbound = None
    if proto == "vless":
        user_id = parsed.get("user","")
        network = params.get("type", params.get("network","ws"))
        security = params.get("security","tls")
        sni = params.get("sni", params.get("host", address))
        fp = params.get("fp","chrome")
        alpn = params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
        path = params.get("path","/")
        host_header = params.get("host", address)
        stream = {"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
        if network=="ws":
            stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
        elif network=="grpc":
            svc = params.get("serviceName","")
            stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
        if security in ["tls","xtls"]:
            stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}
        outbound={"tag":"proxy","protocol":"vless",
                  "settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user_id,"encryption":params.get("encryption","none"),"flow":params.get("flow","")}]}]},
                  "streamSettings":stream}

    elif proto == "trojan":
        password = parsed.get("user","")
        network = params.get("type", params.get("network","ws"))
        security = params.get("security","tls")
        sni = params.get("sni", params.get("host", address))
        fp = params.get("fp","chrome")
        alpn = params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
        path = params.get("path","/")
        host_header = params.get("host", address)
        stream = {"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
        if network=="ws":
            stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
        elif network=="grpc":
            svc = params.get("serviceName","")
            stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
        if security in ["tls","xtls"]:
            stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}
        outbound={"tag":"proxy","protocol":"trojan",
                  "settings":{"servers":[{"address":address,"port":port,"password":password,"flow":params.get("flow","")}]},
                  "streamSettings":stream}

    elif proto == "ss":
        method = parsed.get("method","aes-128-gcm")
        password = parsed.get("user","")
        outbound={"tag":"proxy","protocol":"shadowsocks",
                  "settings":{"servers":[{"address":address,"port":port,"method":method,"password":password}]},
                  "streamSettings":{"network":"tcp","security":"none","sockopt":{"dialerProxy":"fragment"}}}
    elif proto == "vmess":
        user = parsed.get("user","")
        network = parsed.get("params",{}).get("network","tcp")
        outbound={"tag":"proxy","protocol":"vmess",
                  "settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user,"alterId":0,"security":"auto"}]}]},
                  "streamSettings":{"network":network,"security":"tls","sockopt":{"dialerProxy":"fragment"}}}
    else:
        return None

    return {"remarks":remark_with_ping,"log":{"loglevel":"warning"},"inbounds":inbounds_block,
            "outbounds":[outbound,{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],
            "routing":routing_block}

def build_fragment_list_from_parsed(parsed_list, ping_results):
    frags = []
    for p in parsed_list:
        frag = build_fragment(p, ping_results)
        if frag:
            frags.append(frag)
    return frags

# ------------------ Combo generators (exact as provided) ------------------
def generate_combo2(configs: list, cap: int = 200) -> list:
    n = len(configs)
    if n < 2: return []
    indices = [(i,j) for i in range(n) for j in range(i+1,n)]
    random.shuffle(indices)
    combos=[]
    seen=set()
    for i,j in indices:
        combo = f"{configs[i]}+{configs[j]}"
        if combo not in seen:
            combos.append(combo)
            seen.add(combo)
        if len(combos) >= cap:
            break
    return combos

def generate_combo3(configs: list, cap: int = 200) -> list:
    n = len(configs)
    if n < 3: return []
    cands=[]
    for a in range(n):
        for b in range(a+1,n):
            for c in range(b+1,n):
                cands.append((a,b,c))
    random.shuffle(cands)
    combos=[]
    seen=set()
    for i,j,k in cands:
        A,B,C = configs[i],configs[j],configs[k]
        tail = strip_protocol(C)
        combo = f"{A}+{B}+ss://{tail}"
        if combo in seen:
            continue
        seen.add(combo)
        combos.append(combo)
        if len(combos) >= cap:
            break
    return combos

# ------------------ subscription fetch helper ------------------
def fetch_sub_link(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        content = r.text.strip()
        try:
            decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8', errors='ignore')
            if any(p in decoded for p in protocols):
                content = decoded
        except Exception:
            pass
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        return lines
    except Exception as e:
        print(f"[red]Failed to fetch {url}: {e}[/red]")
        return []

# ------------------ Main ------------------
def main():
    print("[bold cyan]Choose input mode:[/bold cyan]")
    print("1) Paste configs manually")
    print("2) Fetch from subscription URL(s)")
    mode = input("Enter choice (1 or 2): ").strip()

    lines = []
    if mode == "2":
        while True:
            url = input("Enter subscription URL (empty to stop): ").strip()
            if not url:
                break
            fetched = fetch_sub_link(url)
            lines.extend(fetched)
            print(f"[green]Fetched {len(fetched)} lines from URL[/green]")
    else:
        print("[cyan]Paste your configs line by line. Press Ctrl+D to finish:[/cyan]")
        try:
            while True:
                l = input().strip()
                if l:
                    lines.append(l)
        except EOFError:
            pass

    lines = list(dict.fromkeys([ln for ln in lines if ln.strip()]))

    if not lines:
        print("[bold red]No configs provided. Exiting.[/bold red]")
        return

    print("\n[bold cyan]Performing ping checks (3 samples)...[/bold cyan]")
    ping_results = {}
    parsed_map = {}
    valid_configs = []

    for cfg in lines:
        if not any(cfg.startswith(p) for p in protocols):
            continue
        host = extract_host(cfg)
        if not host:
            print(f"[bold red][INVALID HOST][/bold red] {cfg}")
            continue
        ms = ping_host(host, count=3)
        status, label = classify_ping(ms)
        print(f"{label} {host} - {ms if ms is not None else 'NO REPLY'} ms")
        ping_results[cfg] = (status, ms)
        parsed = parse_config(cfg)
        if parsed:
            parsed['raw'] = cfg
            parsed_map[cfg] = parsed
            valid_configs.append(cfg)

    vless_list = [c for c in valid_configs if c.startswith("vless://")]
    vmess_list = [c for c in valid_configs if c.startswith("vmess://")]
    trojan_list = [c for c in valid_configs if c.startswith("trojan://")]
    ss_list = [c for c in valid_configs if c.startswith("ss://")]
    green_list = [c for c,(s,_) in ping_results.items() if s == "good"]
    green_yellow_list = [c for c,(s,_) in ping_results.items() if s in ("good","warn")]

    while True:
        print("\n[bold cyan]Select output option:[/bold cyan]")
        print("1) VLESS")
        print("2) VMess")
        print("3) Trojan")
        print("4) Shadowsocks")
        print("5) All configs")
        print("6) Green only")
        print("7) Green + Yellow")
        print("8) Fragmented Config (V2Ray JSON)")
        print("9) Raw parsed JSON")
        print("10) Combo-2")
        print("11) Combo-3")
        print("0) Exit")
        choice = input("Enter choice number: ").strip()

        if choice == "0":
            print("[bold green]Exiting...[/bold green]")
            break

        if choice == "1":
            out_list = vless_list; ext = "txt"
        elif choice == "2":
            out_list = vmess_list; ext = "txt"
        elif choice == "3":
            out_list = trojan_list; ext = "txt"
        elif choice == "4":
            out_list = ss_list; ext = "txt"
        elif choice == "5":
            out_list = valid_configs; ext = "txt"
        elif choice == "6":
            out_list = green_list; ext = "txt"
        elif choice == "7":
            out_list = green_yellow_list; ext = "txt"
        elif choice == "8":
            parsed_list = [parsed_map[cfg] for cfg in valid_configs if cfg in parsed_map]
            fragments = build_fragment_list_from_parsed(parsed_list, ping_results)
            filename = input("Enter filename for Fragment (without extension): ").strip() or "fragmented"
            if not filename.endswith(".json"):
                filename = filename + ".json"
            save_json_file(SAVE_DIR, filename, fragments)
            continue
        elif choice == "9":
            parsed_list = []
            for cfg in valid_configs:
                p = parsed_map.get(cfg)
                if not p:
                    continue
                ping_status, ping_ms = ping_results.get(cfg, (None, None))
                p_copy = dict(p)
                p_copy['ping_status'] = ping_status
                p_copy['ping_ms'] = ping_ms
                parsed_list.append(p_copy)
            filename = input("Enter filename for parsed JSON (without extension): ").strip() or "parsed_configs"
            if not filename.endswith(".json"):
                filename = filename + ".json"
            save_json_file(SAVE_DIR, filename, parsed_list)
            continue
        elif choice == "10":
            combos = generate_combo2(valid_configs, cap=200)
            filename = input("Enter filename for Combo-2 (without extension): ").strip() or "combo2"
            if not filename.endswith(".txt"):
                filename = filename + ".txt"
            save_to_file_list(SAVE_DIR, filename, combos)
            continue
        elif choice == "11":
            combos = generate_combo3(valid_configs, cap=200)
            filename = input("Enter filename for Combo-3 (without extension): ").strip() or "combo3"
            if not filename.endswith(".txt"):
                filename = filename + ".txt"
            save_to_file_list(SAVE_DIR, filename, combos)
            continue
        else:
            print("[bold red]Invalid choice[/bold red]")
            continue

        if not out_list:
            print("[bold red]No items to save for this selection.[/bold red]")
            continue
        filename = input("Enter filename (without extension): ").strip() or "output"
        if not filename.endswith(".txt"):
            filename = filename + ".txt"
        save_to_file_list(SAVE_DIR, filename, out_list)

if __name__ == "__main__":
    main()
