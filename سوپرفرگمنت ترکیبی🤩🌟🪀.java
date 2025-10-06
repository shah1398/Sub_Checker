import os
import re
import subprocess
import json
import base64
from urllib.parse import parse_qs, unquote
from rich import print
from rich.prompt import Prompt
import random

# ------------------ Settings ------------------
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

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

def ping_host(host: str):
    try:
        output = subprocess.check_output(
            ["ping", "-c", "3", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode()
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None
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

def strip_protocol(link: str) -> str:
    if "://" in link:
        return link.split("://", 1)[1]
    return link

# ------------------ Parsers (REPLACED: using code2 parsing logic) ------------------
def parse_vless(link: str):
    try:
        main = link.split("://",1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
            remark = unquote(remark)
        if "?" in main:
            addr_port, params = main.split("?",1)
            query = parse_qs(params)
        else:
            addr_port = main
            query = {}
        if "@" in addr_port:
            user_id, host_port = addr_port.split("@",1)
        else:
            user_id = ""
            host_port = addr_port
        if ":" in host_port:
            address, port = host_port.split(":",1)
        else:
            address = host_port
            port = "443"
        return {
            "protocol":"vless",
            "raw": link,
            "address": address,
            "port": int(port) if str(port).isdigit() else 443,
            "user": user_id,
            "id": user_id,
            "params": {k:v[0] for k,v in query.items()},
            "remark": remark or link
        }
    except:
        return None

def parse_trojan(link: str):
    try:
        main = link.split("://",1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
            remark = unquote(remark)
        if "?" in main:
            addr_port, params = main.split("?",1)
            query = parse_qs(params)
        else:
            addr_port = main
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
            "port":int(port) if port.isdigit() else 443,
            "user":passwd,
            "id":passwd,
            "params":{k:v[0] for k,v in query.items()},
            "remark":remark or link
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
        # Inline user@host:port
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
                "port":int(port) if port.isdigit() else 443,
                "user":password,
                "id":password,
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
                    "port":int(port) if port.isdigit() else 443,
                    "user":password,
                    "id":password,
                    "method":method,
                    "params":{},
                    "remark":remark
                }
    except:
        return None
    return None

def parse_config(conf: str):
    """
    Keeps original name parse_config but uses the improved parsing above.
    """
    conf = conf.strip()
    if conf.startswith("vless://"):
        return parse_vless(conf)
    if conf.startswith("trojan://"):
        return parse_trojan(conf)
    if conf.startswith("ss://"):
        return parse_ss(conf)
    return None

# ------------------ Fragment Builder (REPLACED: using code2 build logic) ------------------
def build_fragment(parsed, ping_results=None):
    """
    Signature kept same as original code: build_fragment(parsed, ping_results=None)
    Implementation adapted from build_fragment_from_parsed in code2 so output matches code2.
    """
    if not parsed:
        return None

    proto = parsed.get("protocol", "vless")
    address = parsed.get("address", "0.0.0.0")
    port = parsed.get("port", 443)
    remark = parsed.get("remark") or f"{proto} fragment"
    params = parsed.get("params", {})

    inbounds_block = [
        {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},
         "sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True},"tag":"socks-in"},
        {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
    ]

    routing_block = {
        "domainStrategy":"IPIfNonMatch",
        "rules":[
            {"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},
            {"network":"tcp","outboundTag":"proxy","type":"field"},
            {"network":"udp","outboundTag":"proxy","type":"field"}
        ]
    }

    # Build streamSettings similar to code2
    network = params.get("type") or params.get("net") or params.get("network") or "ws"
    security = params.get("security")
    if not security:
        if params.get("tls") in ("tls", "true", True, "1"):
            security = "tls"
        else:
            security = "none"

    stream = {"network": network, "security": security, "sockopt": {"dialerProxy": "fragment"}}
    if security in ("tls","xtls"):
        stream["tlsSettings"] = {
            "serverName": params.get("sni") or params.get("host") or address,
            "fingerprint": params.get("fp", "chrome"),
            "alpn": [p.strip() for p in (params.get("alpn") or "").split(",") if p.strip()] or ["http/1.1"]
        }

    if network == "ws":
        stream["wsSettings"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host") or params.get("sni") or address}}
    elif network == "grpc":
        svc = params.get("serviceName","")
        stream["grpcSettings"] = {"serviceName": svc} if svc else {"multiMode": False}
    elif network == "h2":
        stream["httpSettings"] = {"path": params.get("path","/"), "host": [params.get("host", address)]}

    outbound = None
    if proto == "vless":
        user_id = parsed.get("user","") or parsed.get("id","")
        outbound = {
            "tag":"proxy",
            "protocol":"vless",
            "settings":{"vnext":[{"address":address,"port":int(port),"users":[{"id":user_id,"encryption":params.get("encryption","none"),"flow":params.get("flow","")}]}]},
            "streamSettings": stream
        }
    elif proto == "trojan":
        password = parsed.get("user","") or parsed.get("id","")
        outbound = {
            "tag":"proxy",
            "protocol":"trojan",
            "settings":{"servers":[{"address":address,"port":int(port),"password":password,"flow":params.get("flow","")}]},
            "streamSettings": stream
        }
    elif proto == "ss":
        method = parsed.get("method", params.get("method","aes-128-gcm"))
        password = parsed.get("user","") or parsed.get("id","")
        outbound = {
            "tag":"proxy",
            "protocol":"shadowsocks",
            "settings":{"servers":[{"address":address,"port":int(port),"method":method,"password":password}]},
            "streamSettings":{"network":"tcp","security":"none","sockopt":{"dialerProxy":"fragment"}}
        }
    else:
        return None

    fragment = {
        "remarks": remark,
        "log":{"loglevel":"warning"},
        "inbounds": inbounds_block,
        "outbounds": [
            outbound,
            {"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}},
        ],
        "routing": routing_block
    }

    return fragment

# ------------------ Combo Generators ------------------
def generate_combo2(configs: list[str], cap: int = 50) -> list[str]:
    n = len(configs)
    if n < 2: return []
    indices = [(i,j) for i in range(n) for j in range(i+1,n)]
    random.shuffle(indices)
    combos=[]
    seen=set()
    for i,j in indices:
        combo=f"{configs[i]}+{configs[j]}"
        if combo not in seen:
            combos.append(combo)
            seen.add(combo)
        if len(combos)>=cap:
            break
    return combos

def generate_combo3(configs: list[str], cap: int = 50) -> list[str]:
    n = len(configs)
    if n<3: return []
    cands=[]
    for a in range(n):
        for b in range(a+1,n):
            for c in range(b+1,n):
                cands.append((a,b,c))
                if len(cands)>=cap*8:
                    break
            if len(cands)>=cap*8:
                break
        if len(cands)>=cap*8:
            break
    random.shuffle(cands)
    combos=[]
    seen=set()
    for i,j,k in cands:
        A=configs[i];B=configs[j];C=configs[k]
        tail=strip_protocol(C)
        combo=f"{A}+{B}+ss//{tail}"
        if combo in seen:
            continue
        seen.add(combo)
        combos.append(combo)
        if len(combos)>=cap:
            break
    return combos

# ------------------ Main ------------------
def main():
    print("[bold cyan]Enter your configs line by line (VLESS/Trojan/SS only). Ctrl+D when done:[/bold cyan]")
    configs=[]
    while True:
        try:
            line=input()
            if line.strip():
                configs.append(line.strip())
        except EOFError:
            break

    if not configs:
        print("[bold red]No configs entered![/bold red]")
        return

    parsed_list=[]
    protocol_count={"vless":0,"trojan":0,"ss":0,"ignored":0}

    for conf in configs:
        parsed=parse_config(conf)
        if not parsed:
            protocol_count["ignored"]+=1
            print(f"[bold yellow]Ignored (unsupported or invalid):[/bold yellow] {conf}")
            continue
        proto=parsed["protocol"]
        protocol_count[proto]+=1
        parsed_list.append(parsed)
        print(f"[bold cyan]{proto.upper()}[/bold cyan] {parsed['remark']}")

    print("\n[bold green]Summary:[/bold green]")
    for k,v in protocol_count.items():
        print(f"{k}: {v}")
    print(f"Total parsed configs: {len(parsed_list)}")

    while True:
        print("\n[cyan]Choose output type:[/cyan]")
        print("1) Fragment TXT")
        print("2) Combo-2 (2 configs)")
        print("3) Combo-3 (3 configs)")
        print("0) Exit")
        choice = input("Enter choice: ").strip()
        if choice=="0":
            break

        elif choice=="1":
            fragments=[]
            for parsed in parsed_list:
                frag=build_fragment(parsed)
                if frag:
                    fragments.append(frag)
            filename=Prompt.ask("Enter output file name for Fragment (without extension)")
            filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.txt")
            with open(filepath,"w",encoding="utf-8") as f:
                json.dump(fragments,f,ensure_ascii=False,indent=2)
            print(f"[bold green]Fragment saved:[/bold green] {filepath}")

        elif choice=="2":
            combos=generate_combo2(configs)
            filename=Prompt.ask("Enter output file name for Combo-2 (TXT, without extension)")
            filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.txt")
            with open(filepath,"w",encoding="utf-8") as f:
                f.write("\n".join(combos))
            print(f"[bold green]Combo-2 saved ({len(combos)} combos):[/bold green] {filepath}")

        elif choice=="3":
            combos=generate_combo3(configs)
            filename=Prompt.ask("Enter output file name for Combo-3 (TXT, without extension)")
            filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.txt")
            with open(filepath,"w",encoding="utf-8") as f:
                f.write("\n".join(combos))
            print(f"[bold green]Combo-3 saved ({len(combos)} combos):[/bold green] {filepath}")

        else:
            print("[bold red]Invalid choice![/bold red]")

if __name__=="__main__":
    main()

