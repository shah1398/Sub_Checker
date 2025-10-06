#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import urllib.parse
import subprocess
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn

# ---------------- تنظیمات مسیر خروجی ----------------
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAX_THREADS = 20
PING_COUNT = 3

# ---------------- استخراج هاست و پروتکل ----------------
def extract_host(config: str) -> str:
    try:
        if "://" not in config:
            return config
        proto, rest = config.split("://", 1)
        if proto == "ss":
            rest = rest.split("#")[0]
            if "@" in rest:
                host = rest.rsplit("@",1)[1].split(":",1)[0]
                return host
        m = re.search(r"@([^:/?#\s]+)", rest)
        if m:
            return m.group(1)
        m2 = re.search(r"://([^:/?#\s]+)", config)
        return m2.group(1) if m2 else "0.0.0.0"
    except:
        return "0.0.0.0"

def extract_protocol(config: str) -> str:
    if "://" in config:
        return config.split("://", 1)[0].lower()
    return "unknown"

# ---------------- پینگ دقیق ----------------
def ping_host(host: str) -> float:
    results = []
    for _ in range(PING_COUNT):
        try:
            r = ping(host, timeout=1, unit="ms")
            if r is not None:
                results.append(r)
        except:
            continue
    if results:
        # حذف outlier و میانگین
        results.sort()
        if len(results) > 2:
            results = results[1:-1]
        return sum(results)/len(results)
    return float('inf')

def classify_latency(ms: float) -> str:
    if ms == float('inf'):
        return "bad"
    if ms < 150:
        return "good"
    if ms < 300:
        return "warn"
    return "bad"

# ---------------- پارسر پیشرفته ----------------
def parse_link(link: str) -> dict:
    link = link.strip()
    result = {
        "protocol": "unknown",
        "address": "0.0.0.0",
        "port": 443,
        "id": "",
        "remark": link,
        "params": {}
    }
    try:
        if "://" not in link:
            return result
        proto, main = link.split("://", 1)
        result["protocol"] = proto.lower()
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
            remark = urllib.parse.unquote(remark)
        result["remark"] = remark or link
        params = {}
        if "?" in main:
            main, q = main.split("?",1)
            for k,v in urllib.parse.parse_qs(q).items():
                params[k] = v[0]
        result["params"] = params
        if "@" in main:
            user, host_port = main.split("@",1)
            result["id"] = user
        else:
            host_port = main
        if ":" in host_port:
            address, port = host_port.split(":",1)
            result["address"] = address
            result["port"] = int(port)
        else:
            result["address"] = host_port
        return result
    except:
        return result

# ---------------- ساخت فرگمنت کامل ----------------
def build_fragment(cfg: dict) -> dict:
    proto = cfg.get("protocol","vless")
    address = cfg.get("address","0.0.0.0")
    port = cfg.get("port",443)
    user_id = cfg.get("id","")
    remark = cfg.get("remark","proxy")
    params = cfg.get("params",{})

    network = params.get("type","ws")
    security = params.get("security","tls")
    tlsSettings = None
    if security.lower() in ("tls","xtls"):
        tlsSettings = {
            "serverName": params.get("sni") or address,
            "fingerprint": params.get("fp","chrome"),
            "alpn": [p.strip() for p in (params.get("alpn","http/1.1").split(","))]
        }

    streamSettings = {"network": network,"security":security,"sockopt":{"dialerProxy":"fragment"}}
    if network=="ws":
        streamSettings["wsSettings"]={"path":params.get("path","/"),"headers":{"Host":params.get("host") or address}}
    if network=="grpc":
        streamSettings["grpcSettings"]={"serviceName":params.get("serviceName","")}
    if tlsSettings:
        streamSettings["tlsSettings"]=tlsSettings

    if proto in ("vless","vmess"):
        outbound = {"tag":"proxy","protocol":proto,"settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user_id,"encryption":params.get("encryption","none")}]}]},"streamSettings":streamSettings}
    elif proto=="trojan":
        outbound = {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":address,"port":port,"password":user_id}]},"streamSettings":streamSettings}
    elif proto in ("ss","shadowsocks"):
        outbound = {"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":address,"port":port,"method":params.get("method","aes-128-gcm"),"password":user_id}]},"streamSettings":streamSettings}
    else:
        outbound = {"tag":"proxy","protocol":"freedom","settings":{}}

    fragment = {
        "remarks": remark,
        "log":{"loglevel":"warning"},
        "dns":{"servers":[{"address":"https://1.1.1.1/dns-query","tag":"remote-dns"},"1.1.1.1","8.8.8.8"],"queryStrategy":"UseIP"},
        "inbounds":[
            {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},"tag":"socks-in","sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True}},
            {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
        ],
        "outbounds":[
            outbound,
            {"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}},
            {"tag":"dns-out","protocol":"dns","settings":{}}
        ],
        "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},{"network":"tcp","outboundTag":"proxy","type":"field"},{"network":"udp","outboundTag":"proxy","type":"field"}]}
    }
    return fragment

# ---------------- ذخیره خروجی ----------------
def save_fragments(fragments: list):
    fname = input("Enter filename (default: fragment.json): ").strip() or "fragment"
    path = os.path.join(OUTPUT_FOLDER,fname+".json")
    with open(path,"w",encoding="utf-8") as f:
        json.dump(fragments,f,ensure_ascii=False,indent=2)
    print(f"[green]✅ Saved {len(fragments)} fragments -> {path}[/green]")

# ---------------- جدول رنگی ----------------
def print_summary(results: list):
    table = Table(title="Ping Summary")
    table.add_column("Config")
    table.add_column("Protocol")
    table.add_column("Latency(ms)")
    table.add_column("Status")
    counts = {"good":0,"warn":0,"bad":0}
    proto_counts = {}
    for r in results:
        ms = r["latency"]
        status = classify_latency(ms)
        counts[status] += 1
        proto_counts[r["protocol"]] = proto_counts.get(r["protocol"],0)+1
        avg_str = f"{ms:.2f}" if ms!=float('inf') else "-"
        color = {"good":"green","warn":"yellow","bad":"red"}[status]
        table.add_row(r["config"],r["protocol"].upper(),avg_str,f"[{color}]{status.upper()}[/{color}]")
    print(table)
    proto_table = Table(title="Protocol Counts")
    proto_table.add_column("Protocol")
    proto_table.add_column("Count")
    for k,v in proto_counts.items():
        proto_table.add_row(k.upper(),str(v))
    print(proto_table)
    print(f"[green]Good:{counts['good']}  [yellow]Warn:{counts['warn']}  [red]Bad:{counts['bad']}[/green]")

# ---------------- هسته اصلی ----------------
def main():
    print("[cyan]Paste your configs (any protocol), Ctrl+D to finish:[/cyan]")
    lines=[]
    while True:
        try:
            line=input().strip()
            if line:
                lines.append(line)
        except EOFError:
            break
    if not lines:
        print("[red]No configs entered![/red]")
        return

    # پینگ موازی
    results=[]
    fragments=[]
    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn()) as prog:
        task = prog.add_task("[cyan]Pinging hosts...",total=len(lines))
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(ping_host,extract_host(cfg)):cfg for cfg in lines}
            for fut in as_completed(futures):
                cfg= futures[fut]
                ms = fut.result()
                results.append({"config":cfg,"protocol":extract_protocol(cfg),"latency":ms})
                prog.update(task,advance=1)

    print_summary(results)

    # ساخت فرگمنت برای کانفیگ‌های خوب و زرد
    valid = [r["config"] for r in results if classify_latency(r["latency"]) in ("good","warn")]
    for cfg in valid:
        parsed = parse_link(cfg)
        frag = build_fragment(parsed)
        fragments.append(frag)

    save_fragments(fragments)

if __name__=="__main__":
    main()
