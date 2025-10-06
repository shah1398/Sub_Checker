import os
import re
import sys
import json
import urllib.parse
from ping3 import ping
from rich import print
from time import sleep

# ===== مسیر ذخیره خروجی =====
SAVE_PATH = "/sdcard/Download/Akbar98/"
os.makedirs(SAVE_PATH, exist_ok=True)

protocols = ["vless://", "vmess://", "trojan://", "ss://", "grpc://"]

# ======= تابع پالس ثابت =======
def parse_link(link):
    """
    پارس کننده لینک‌های vless:// ، trojan:// و ss://
    خروجی: (proto, parsed_dict) یا (None, None) در صورت خطا
    parsed_dict شامل:
      - protocol, address, port, user, params (dict), remark, raw
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

        return proto, {
            "protocol": proto,
            "address": address,
            "port": int(port) if port.isdigit() else 443,
            "user": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": urllib.parse.unquote(remark),
            "raw": link
        }
    except Exception:
        return None, None

# ======= استخراج هاست برای پینگ =======
def extract_host(link):
    try:
        if link.startswith("ss://"):
            import base64
            encoded = link[5:].split("#")[0] + "==="
            decoded = base64.urlsafe_b64decode(encoded.encode()).decode()
            host = decoded.split("@")[1].split(":")[0]
            return host
        match = re.search(r'@([^:/?#]+)', link)
        return match.group(1) if match else None
    except:
        return None

def ping_host(host, count=3):
    delays = []
    for _ in range(count):
        delay = ping(host, timeout=1.5)
        if delay is not None:
            delays.append(delay*1000)
        sleep(0.2)
    return sum(delays)/len(delays) if delays else None

# ======= تابع ساخت فرگمنت سوم بهینه =======
def fragment_v3_optimized(configs, ping_results=None):
    fragments = []

    for i, cfg in enumerate(configs):
        proto, parsed = parse_link(cfg)
        if not parsed:
            host = extract_host(cfg) or "0.0.0.0"
            parsed = {
                "protocol": "vless",
                "address": host,
                "port": 443,
                "user": "user",
                "params": {},
                "remark": cfg,
                "raw": cfg
            }
            proto = "vless"

        # پینگ و وضعیت
        status, ping_val = (None, None)
        if ping_results and parsed["raw"] in ping_results:
            status, ping_val = ping_results[parsed["raw"]]

        ping_str = f"{ping_val:.2f} ms" if ping_val is not None else "NO REPLY"
        remark_with_ping = f"{parsed.get('remark', f'Config {i+1}')} | {ping_str} | {status.upper() if status else ''}"

        address = parsed.get("address", "0.0.0.0")
        port = parsed.get("port", 443)
        user = parsed.get("user", "user")
        params = parsed.get("params", {})

        # inbounds
        inbounds_block = [
            {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},
             "sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True},"tag":"socks-in"},
            {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
        ]

        # routing
        routing_block = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},
                {"network":"tcp","outboundTag":"proxy","type":"field"}
            ]
        }

        # outbound بر اساس پروتکل
        outbound = None
        if proto == "vless":
            network = params.get("type", "ws")
            security = params.get("security", "tls")
            sni = params.get("sni", params.get("host", address))
            fp = params.get("fp", "chrome")
            alpn = params.get("alpn", "http/1.1").split(",") if "alpn" in params else ["http/1.1"]
            path = params.get("path", "/")
            host_header = params.get("host", address)

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
                "protocol": "vless",
                "settings": {
                    "vnext":[{"address": address, "port": port, "users":[{"id": user, "encryption":"none","flow": params.get("flow","")}]}]
                },
                "streamSettings": stream
            }

        elif proto == "trojan":
            password = user
            network = params.get("type","ws")
            security = params.get("security","tls")
            sni = params.get("sni", params.get("host", address))
            fp = params.get("fp","chrome")
            alpn = params.get("alpn","http/1.1").split(",") if "alpn" in params else ["http/1.1"]
            path = params.get("path","/")
            host_header = params.get("host", address)

            stream = {"network": network, "security": security, "sockopt": {"dialerProxy":"fragment"}}
            if network=="ws":
                stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
            elif network=="grpc":
                svc = params.get("serviceName","")
                stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
            if security in ["tls","xtls"]:
                stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}

            outbound = {
                "tag":"proxy",
                "protocol":"trojan",
                "settings":{"servers":[{"address":address,"port":port,"password":password}]},
                "streamSettings":stream
            }

        elif proto in ["ss","shadowsocks"]:
            method = params.get("method","aes-128-gcm")
            password = user
            outbound = {
                "tag":"proxy",
                "protocol":"shadowsocks",
                "settings":{"servers":[{"address":address,"port":port,"method":method,"password":password}]},
                "streamSettings":{"network":"tcp","security":"none","sockopt":{"dialerProxy":"fragment"}}
            }

        else:
            continue

        fragment = {
            "remarks": remark_with_ping,
            "log":{"loglevel":"warning"},
            "inbounds": inbounds_block,
            "outbounds":[
                outbound,
                {"tag":"fragment","protocol":"freedom",
                 "settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},
                            "domainStrategy":"UseIPv4v6"}}
            ],
            "routing": routing_block
        }

        fragments.append(fragment)

    return fragments

# ======= MAIN =======
def main():
    print("[cyan]Paste your configs (any protocol). Press Ctrl+D to finish:[/cyan]")
    lines=[]
    while True:
        try:
            line=input().strip()
            if line: lines.append(line)
        except EOFError:
            break
    if not lines:
        print("[red]No configs entered[/red]")
        sys.exit(0)

    # ===== پینگ دقیق و رنگی =====
    live_configs=[]
    print("[cyan]\nChecking ping for all configs (3 samples per host)...[/cyan]")
    for cfg in lines:
        host=extract_host(cfg)
        if not host:
            print(f"[magenta]No host: {cfg}[/magenta]")
            continue
        delay=ping_host(host,count=3)
        if delay is None:
            print(f"[red]FAIL {host}[/red]")
        elif delay<100:
            print(f"[green]GOOD {host} - {delay:.1f}ms[/green]")
            live_configs.append(cfg)
        elif delay<300:
            print(f"[yellow]WARN {host} - {delay:.1f}ms[/yellow]")
            live_configs.append(cfg)
        else:
            print(f"[red]BAD {host} - {delay:.1f}ms[/red]")

    if not live_configs:
        print("[red]No live configs passed ping. Exiting.[/red]")
        sys.exit(0)

    # ===== ساخت فرگمنت بهینه =====
    fragments=fragment_v3_optimized(live_configs)

    fname=input("Enter output filename (without extension): ").strip() or "fragment_output"
    path=os.path.join(SAVE_PATH,f"{fname}.json")
    with open(path,"w",encoding="utf-8") as f:
        json.dump(fragments,f,indent=2,ensure_ascii=False)
    print(f"[green]✅ Fragment saved to: {path}[/green]")

if __name__=="__main__":
    main()