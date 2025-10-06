#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import time
import random
import base64
from urllib.parse import unquote, parse_qs
from typing import List, Dict, Any, Optional
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import urllib.parse

# ==================== Settings ====================
SAVE_DIR = "/storage/emulated/0/Download/almasi98"
os.makedirs(SAVE_DIR, exist_ok=True)
MAX_THREADS = 20
PING_COUNT = 3
MAX_COMBO = 50

# ==================== Helpers ====================
def extract_host(cfg: str) -> Optional[str]:
    m = re.search(r"@([^:/?#\s]+)", cfg)
    if m: return m.group(1)
    m2 = re.search(r"://([^:/?#\s]+)", cfg)
    return m2.group(1) if m2 else None

def extract_protocol(cfg: str) -> str:
    return cfg.split("://")[0].lower() if "://" in cfg else "unknown"

def ping_host(host: str) -> Optional[float]:
    try:
        output = subprocess.check_output(["ping","-c","3","-W","1",host], stderr=subprocess.DEVNULL).decode(errors="ignore")
        m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        return float(m.group(1)) if m else None
    except: return None

def ping_ping3(host: str) -> Optional[float]:
    results=[]
    for _ in range(PING_COUNT):
        try:
            r=ping(host, timeout=1, unit="ms")
            if r is not None: results.append(r)
        except: continue
    return sum(results)/len(results) if results else None

def classify_ping(ms: Optional[float]):
    if ms is None: return "bad", "[bold red][BAD][/bold red]"
    if ms < 150: return "good", "[bold green][GOOD][/bold green]"
    if ms < 300: return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ==================== Input ====================
print("[cyan]Enter your configs line by line (Ctrl+D when done):[/cyan]")
configs=[]
while True:
    try:
        line=input()
        if line.strip(): configs.append(line.strip())
    except EOFError:
        break
if not configs:
    print("[red]No configs entered![/red]"); exit()

# ==================== Ping & Stats ====================
protocol_count: Dict[str,int]={}
results: List[Dict[str,Any]]=[]

def process(cfg:str):
    host=extract_host(cfg)
    if not host: return cfg,None,None,"ignored","ignored"
    sub_ms=ping_host(host)
    ping3_ms=ping_ping3(host)
    status_sub,_=classify_ping(sub_ms)
    status_ping3,_=classify_ping(ping3_ms)
    return cfg,sub_ms,ping3_ms,status_sub,status_ping3

with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn()) as prog:
    task=prog.add_task("[cyan]Pinging hosts...", total=len(configs))
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures={executor.submit(process,cfg):cfg for cfg in configs}
        for fut in as_completed(futures):
            cfg,sub_ms,ping3_ms,status_sub,status_ping3=fut.result()
            proto=extract_protocol(cfg)
            if status_sub=="ignored" and status_ping3=="ignored":
                continue
            protocol_count[proto]=protocol_count.get(proto,0)+1
            results.append({"config":cfg,"protocol":proto,"sub_ms":sub_ms,"ping3_ms":ping3_ms,"status_sub":status_sub,"status_ping3":status_ping3})
            prog.update(task,advance=1)

# ==================== Summary ====================
table=Table(title="Configs Summary")
table.add_column("Config"); table.add_column("Proto"); table.add_column("Sub(ms)"); table.add_column("Sub Status"); table.add_column("Ping3(ms)"); table.add_column("Ping3 Status")
for r in results:
    table.add_row(r["config"], r["protocol"].upper(), str(r["sub_ms"]) if r["sub_ms"] else "-", r["status_sub"].upper(), str(r["ping3_ms"]) if r["ping3_ms"] else "-", r["status_ping3"].upper())
print(table)
proto_table=Table(title="Protocol Counts"); proto_table.add_column("Proto"); proto_table.add_column("Count")
for k,v in protocol_count.items(): proto_table.add_row(k.upper(),str(v))
print(proto_table)

# ==================== Parser جدید ====================
def parse_link(link):
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

# ==================== Fragment Builder جدید ====================
def build_fragment(parsed, ping_results=None):
    if not parsed:
        return None
    proto = parsed["protocol"]
    address = parsed["address"]
    port = parsed["port"]
    remark = parsed["remark"] or f"{proto} fragment"
    raw = parsed["raw"]
    params = parsed.get("params", {})
    status, ping = (None, None)
    if ping_results and raw in ping_results:
        status, ping = ping_results[raw]
    ping_str = f"{ping:.2f} ms" if ping is not None else "NO REPLY"
    remark_with_ping = f"{remark} | {ping_str} | {status.upper() if status else ''}"
    inbounds_block = [
        {"port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":True,"userLevel":8},"sniffing":{"destOverride":["http","tls"],"enabled":True,"routeOnly":True},"tag":"socks-in"},
        {"port":10853,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}
    ]
    routing_block = {"domainStrategy":"IPIfNonMatch","rules":[{"inboundTag":["dns-in"],"outboundTag":"dns-out","type":"field"},{"network":"tcp","outboundTag":"proxy","type":"field"}]}
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
        if network=="ws": stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
        elif network=="grpc": svc=params.get("serviceName",""); stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
        if security in ["tls","xtls"]: stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}
        outbound = {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":address,"port":port,"users":[{"id":user_id,"encryption":params.get("encryption","none"),"flow":params.get("flow","")}]}]},"streamSettings":stream}
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
        if network=="ws": stream["wsSettings"]={"path":path,"headers":{"Host":host_header}}
        elif network=="grpc": svc=params.get("serviceName",""); stream["grpcSettings"]={"serviceName":svc} if svc else {"multiMode":False}
        if security in ["tls","xtls"]: stream["tlsSettings"]={"serverName":sni,"fingerprint":fp,"alpn":alpn}
        outbound = {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":address,"port":port,"password":password,"flow":params.get("flow","")}]},"streamSettings":stream}
    elif proto == "ss":
        method = params.get("method","aes-128-gcm")
        password = parsed.get("user","")
        outbound = {"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":address,"port":port,"method":method,"password":password}]},"streamSettings":{"network":"tcp","security":"none","sockopt":{"dialerProxy":"fragment"}}}
    else: return None
    return {"remarks":remark_with_ping,"log":{"loglevel":"warning"},"inbounds":inbounds_block,"outbounds":[outbound,{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},"domainStrategy":"UseIPv4v6"}}],"routing":routing_block}

# ==================== Combos ====================
def strip_proto(link:str): return link.split("://",1)[1] if "://" in link else link

def combo2(cfgs:List[str],cap:int=MAX_COMBO):
    n=len(cfgs); indices=[(i,j) for i in range(n) for j in range(i+1,n)]; random.shuffle(indices); combos=[]; seen=set()
    for i,j in indices:
        c=f"{cfgs[i]}+{cfgs[j]}" 
        if c not in seen: combos.append(c); seen.add(c)
        if len(combos)>=cap: break
    return combos

def combo3(cfgs:List[str],cap:int=MAX_COMBO):
    n=len(cfgs); cands=[]; combos=[]; seen=set()
    for a in range(n):
        for b in range(a+1,n):
            for c in range(b+1,n):
                cands.append((a,b,c))
                if len(cands)>=cap*8: break
            if len(cands)>=cap*8: break
        if len(cands)>=cap*8: break
    random.shuffle(cands)
    for i,j,k in cands:
        A,B,C=cfgs[i],cfgs[j],cfgs[k]; tail=strip_proto(C)
        combo=f"{A}+{B}+ss//{tail}"
        if combo in seen: continue
        seen.add(combo)
        combos.append(combo)
        if len(combos)>=cap: break
    return combos

# ==================== Output Menu ====================
def ask_file(def_name:str,ext:str=".txt"): 
    n=input(f"Enter filename (default {def_name}): ").strip(); n=n or def_name
    if not n.endswith(ext): n+=ext
    return os.path.join(SAVE_DIR,n)

def outputs(configs:List[Dict[str,Any]]):
    while True:
        print("\n[cyan]Choose output:[/cyan]")
        print("1) VLESS")
        print("2) TROJAN")
        print("3) SHADOWSOCKS")
        print("4) Combo-2")
        print("5) Combo-3")
        print("6) Fragment JSON")
        print("0) Exit")
        choice=input("Choice: ").strip()
        if choice=="0": break
        raw=[c["remark"] for c in configs]
        if choice=="1": proto="vless"
        elif choice=="2": proto="trojan"
        elif choice=="3": proto="ss"
        else: proto=None
        if proto:
            lst=[c["remark"] for c in configs if c["protocol"]==proto]; path=ask_file(proto); 
            with open(path,"w",encoding="utf-8") as f: f.write("\n".join(lst))
            print(f"[green]Saved {proto} ({len(lst)}) -> {path}[/green]")
        elif choice=="4":
            lst=combo2(raw); path=ask_file("combo2"); 
            with open(path,"w",encoding="utf-8") as f: f.write("\n".join(lst))
            print(f"[green]Saved Combo-2 ({len(lst)}) -> {path}[/green]")
        elif choice=="5":
            lst=combo3(raw); path=ask_file("combo3"); 
            with open(path,"w",encoding="utf-8") as f: f.write("\n".join(lst))
            print(f"[green]Saved Combo-3 ({len(lst)}) -> {path}[/green]")
        elif choice=="6":
            frags=[build_fragment(parse_link(c["remark"])[1]) for c in configs]
            path=ask_file("fragment",".json")
            with open(path,"w",encoding="utf-8") as f: json.dump(frags,f,ensure_ascii=False,indent=2)
            print(f"[green]Saved {len(frags)} fragments -> {path}[/green]")
        else: print("[red]Invalid choice[/red]")

# ==================== MAIN ====================
if __name__=="__main__":
    accepted=[r["config"] for r in results if r["status_sub"]!="bad" or r["status_ping3"]!="bad"]
    configs_dicts=[]
    for cfg in accepted:
        configs_dicts.append({"protocol":extract_protocol(cfg),"address":extract_host(cfg) or "example.com","port":443,"id":"uuid","remark":cfg,"params":{}})
    outputs(configs_dicts)
