import os
import re
import subprocess
import json
from urllib.parse import parse_qs, unquote
from rich import print
from rich.prompt import Prompt
from time import sleep
import random

protocols = ["vmess://", "vless://", "trojan://", "ss://"]

SAVE_PATH = "/storage/emulated/0/Download/Akbar98"
os.makedirs(SAVE_PATH, exist_ok=True)

# ==================== توابع اصلی ====================
def extract_host(config):
    match = re.search(r"@([^:/?#]+)", config)
    return match.group(1) if match else None

def ping_host(host):
    delays=[]
    for _ in range(3):
        try:
            output = subprocess.check_output(
                ["ping", "-c", "1", "-W", "1", host],
                stderr=subprocess.DEVNULL
            ).decode()
            match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
            if match: delays.append(float(match.group(1)))
        except: pass
        sleep(0.2)
    return sum(delays)/len(delays) if delays else None

def classify_ping(ping):
    if ping is None:
        return "bad", "[bold red][BAD][/bold red]"
    elif ping < 150:
        return "good", "[bold green][GOOD][/bold green]"
    else:
        return "warn", "[bold yellow][WARN][/bold yellow]"

# ==================== parse لینک ====================
def parse_link(link: str):
    link = link.strip()
    proto=None
    parsed=None
    try:
        if link.startswith("vless://"): proto="vless"
        elif link.startswith("trojan://"): proto="trojan"
        elif link.startswith("ss://"): proto="ss"
        else: return None
        main=link.split("://",1)[1]
        remark=""
        if "#" in main:
            main, remark = main.split("#",1)
            remark=unquote(remark)
        if "?" in main:
            addr_port, params = main.split("?",1)
            query=parse_qs(params)
        else:
            addr_port=main
            query={}
        if "@" in addr_port:
            user, host_port = addr_port.split("@",1)
        else:
            user=""
            host_port=addr_port
        if ":" in host_port:
            address, port = host_port.split(":",1)
        else:
            address=host_port
            port="443"
        parsed={
            "protocol":proto,
            "address":address,
            "port":int(port) if port.isdigit() else 443,
            "id":user,
            "params":{k:v[0] for k,v in query.items()},
            "remark":remark or address,
            "raw":link
        }
    except:
        parsed=None
    return parsed

# ==================== تابع جایگزین ساخت فرگمنت ====================
def build_fragments(parsed_configs):
    fragments=[]
    for i,cfg in enumerate(parsed_configs):
        address=cfg["address"]
        port=cfg["port"]
        proto=cfg["protocol"]
        remark=cfg.get("remark", f"{proto}_{i+1}")
        params=cfg.get("params", {})

        # ===== پینگ و رنگ‌بندی برای ترمینال =====
        ping_val=ping_host(address)
        status,label=classify_ping(ping_val)
        ping_str=f"{ping_val:.2f} ms" if ping_val else "NO REPLY"
        print(f"{label} {remark} -> {address}:{port} ({proto.upper()}) [{ping_str}]")

        # برای خروجی JSON فقط اسم کانفینگ بدون ping و status
        remark_clean = remark

        # ===== inbounds و routing =====
        inbounds=[
            {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},
             "sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True},"tag":"socks-in"},
            {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
        ]
        routing={
            "domainStrategy":"IPIfNonMatch",
            "rules":[{"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},
                     {"network":"tcp","outboundTag":"proxy","type":"field"}]
        }

        # ===== outbound بر اساس پروتکل =====
        outbound=None
        if proto=="vless":
            user_id=cfg.get("id","")
            network=params.get("type","ws")
            security=params.get("security","tls")
            sni=params.get("sni",params.get("host",address))
            fp=params.get("fp","chrome")
            alpn=params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
            path=params.get("path","/")
            host_header=params.get("host",address)
            stream={"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
            if network=="ws": stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
            elif network=="grpc":
                svc=params.get("serviceName","")
                stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
            if security in ["tls","xtls"]: stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}
            outbound={"tag":"proxy","protocol":"vless",
                      "settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user_id,"encryption":params.get("encryption","none"),"flow":params.get("flow","")}]}]},
                      "streamSettings":stream}
        elif proto=="trojan":
            password=cfg.get("id","")
            network=params.get("type","ws")
            security=params.get("security","tls")
            sni=params.get("sni",params.get("host",address))
            fp=params.get("fp","chrome")
            alpn=params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
            path=params.get("path","/")
            host_header=params.get("host",address)
            stream={"network":network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
            if network=="ws": stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
            elif network=="grpc":
                svc=params.get("serviceName","")
                stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
            if security in ["tls","xtls"]: stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}
            outbound={"tag":"proxy","protocol":"trojan",
                      "settings":{"servers":[{"address":address,"port":port,"password":password,"flow":params.get("flow","")}]},
                      "streamSettings":stream}
        elif proto=="ss":
            method=params.get("method","aes-128-gcm")
            password=cfg.get("id","")
            outbound={"tag":"proxy","protocol":"shadowsocks",
                      "settings":{"servers":[{"address":address,"port":port,"method":method,"password":password}]},
                      "streamSettings":{"network":"tcp","security":"none","sockopt":{"dialerProxy":"fragment"}}}
        else: continue

        fragments.append({"remarks":remark_clean,"log":{"loglevel":"warning"},"inbounds":inbounds,
                          "outbounds":[outbound,{"tag":"fragment","protocol":"freedom",
                                                 "settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],
                          "routing":routing})
    return fragments

# ==================== کمبوها ====================
def generate_combo2(configs):
    combos = []
    for i in range(0, len(configs)-1, 2):
        combos.append(f"{configs[i]}+{configs[i+1]}")
    return combos

def generate_combo3(configs):
    combos = []
    for i in range(0, len(configs)-2, 3):
        tail = configs[i+2]
        if tail.startswith("ss://"):
            tail_stripped = tail
        else:
            tail_stripped = "ss://" + tail.split("://",1)[1]
        combos.append(f"{configs[i]}+{configs[i+1]}+{tail_stripped}")
    return combos

# ==================== Save Helper ====================
def save_output(data, folder, default_name="output", is_json=True):
    fname = Prompt.ask(f"Enter filename (default: {default_name})", default=default_name)
    path=os.path.join(folder,fname+".json" if is_json else ".txt")
    with open(path,"w",encoding="utf-8") as f:
        if is_json: json.dump(data,f,ensure_ascii=False,indent=2)
        else: f.write("\n".join(data))
    print(f"[green]✅ Saved to {path}[/green]")

# ==================== MAIN LOOP ====================
def main():
    print("[bold cyan]Enter configs line by line. Ctrl+D to finish:[/bold cyan]")
    lines=[]
    while True:
        try:
            line=input()
            if line.strip():
                lines.append(line.strip())
        except EOFError:
            break

    valid_configs = [c for c in lines if any(c.startswith(p) for p in protocols)]
    if not valid_configs:
        print("[bold red]No valid configs entered[/bold red]")
        return

    ping_results={}
    for conf in valid_configs:
        host=extract_host(conf)
        ping=ping_host(host)
        status,label=classify_ping(ping)
        ping_results[conf]=(ping,status)
        print(f"{label} {host} - {str(ping)+' ms' if ping else 'NO REPLY'}")

    folder=SAVE_PATH

    while True:
        print("\n[bold cyan]Select output option:[/bold cyan]")
        print("1) Fragment JSON")
        print("2) Combo-2")
        print("3) Combo-3")
        print("0) Exit")
        choice=Prompt.ask("Enter choice",choices=["0","1","2","3"])
        if choice=="0": break
        elif choice=="1":
            parsed_list=[]
            for cfg in valid_configs:
                parsed=parse_link(cfg)
                if parsed: parsed_list.append(parsed)
            fragments=build_fragments(parsed_list)
            save_output(fragments, folder, default_name="fragment", is_json=True)
        elif choice=="2":
            combos=generate_combo2(valid_configs)
            save_output(combos, folder, default_name="combo2", is_json=False)
        elif choice=="3":
            combos=generate_combo3(valid_configs)
            save_output(combos, folder, default_name="combo3", is_json=False)

if __name__=="__main__":
    main()
