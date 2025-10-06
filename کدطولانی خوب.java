import os
import re
import subprocess
import json
import base64
from urllib.parse import parse_qs, unquote
from rich import print
from rich.prompt import Prompt
import random
from typing import Dict, Any, Optional
import requests

# ------------------ Settings ------------------
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ------------------ Helpers ------------------
def safe_b64_decode(s: str) -> Optional[bytes]:
    if not isinstance(s, str):
        return None
    s = s.strip().split("#", 1)[0]
    s = s.replace("\n", "")
    padding = (-len(s)) % 4
    s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        try:
            return base64.b64decode(s)
        except Exception:
            return None

def extract_protocol(cfg: str) -> str:
    if "://" in cfg:
        return cfg.split("://", 1)[0].lower()
    return "unknown"

def extract_host(cfg: str) -> Optional[str]:
    try:
        cfg = cfg.strip()
        if cfg.startswith("ss://"):
            body = cfg[5:].split("#", 1)[0]
            dec = safe_b64_decode(body)
            if dec:
                try:
                    ds = dec.decode(errors="ignore")
                    if "@" in ds:
                        host_part = ds.rsplit("@", 1)[1]
                        host = host_part.split(":", 1)[0]
                        return host
                except Exception:
                    pass
            if "@" in body:
                host_part = body.rsplit("@", 1)[1]
                return host_part.split(":", 1)[0]
            return None
        m = re.search(r"@([^:/?#\s]+)", cfg)
        if m:
            return m.group(1)
        m2 = re.search(r"://([^:/?#\s]+)", cfg)
        if m2:
            return m2.group(1)
        m3 = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", cfg)
        if m3:
            return m3.group(1)
    except Exception:
        return None
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
        return "bad", "[bold red]BAD[/bold red]"
    elif ping < 150:
        return "good", "[bold green]GOOD[/bold green]"
    elif ping < 300:
        return "warn", "[bold yellow]WARN[/bold yellow]"
    else:
        return "bad", "[bold red]BAD[/bold red]"

def strip_protocol(link: str) -> str:
    if "://" in link:
        return link.split("://", 1)[1]
    return link
    # ------------------ Parsers & Fragment Builders ------------------
def parse_config(conf: str) -> Dict[str, Any]:
    proto = extract_protocol(conf)
    raw = conf
    remark = conf
    params: Dict[str, Any] = {}
    user = ""
    host = extract_host(conf) or ""
    port = 443
    try:  
        main = conf.split("://", 1)[1] if "://" in conf else conf
        if "#" in main:  
            main, frag = main.split("#", 1)  
            remark = unquote(frag) or remark
        qstr = ""  
        if "?" in main:  
            before_q, qstr = main.split("?", 1)  
        else:  
            before_q = main
        if "@" in before_q:  
            user_part, host_port = before_q.split("@", 1)  
            user = user_part  
        else:  
            host_port = before_q  
        host_port = host_port.strip()  
        if ":" in host_port:  
            h, p_raw = host_port.split(":", 1)  
            host = h or host  
            p_digits = re.match(r"(\d+)", p_raw)  
            if p_digits:  
                try:  
                    port = int(p_digits.group(1))  
                except Exception:  
                    port = 443  
            else:  
                port = 443  
        else:  
            host = host_port or host  
            port = 443  
        if qstr:  
            parsed_q = parse_qs(qstr)  
            params = {k: v[0] for k, v in parsed_q.items() if v}  
    except Exception:  
        try:  
            m = re.search(r"@([^:/?#\s]+)", conf)  
            if m:  
                host = m.group(1)  
            m2 = re.search(r"://([^:/?#\s]+)", conf)  
            if m2:  
                host = m2.group(1)  
            p_match = re.search(r":(\d{2,5})", conf)  
            if p_match:  
                port = int(p_match.group(1))  
        except Exception:  
            pass  
    return {"raw": raw, "protocol": proto, "remark": remark, "user": user, "host": host, "port": int(port), "params": params}

def build_fragment_v1(parsed: Dict[str, Any], ping_results=None):
    # مشابه کد اصلی build_fragment، سبک V1
    # ...
    return {"fragment": "V1", "parsed": parsed}

def build_fragment_v2(parsed: Dict[str, Any], ping_results=None):
    # V2: بهینه، با ping و streamSettings واقعی
    # ...
    return {"fragment": "V2", "parsed": parsed}

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
    while True:
        print("\n[bold cyan]Select input method:[/bold cyan]")
        print("1) Enter configs manually")
        print("2) Enter subscription links")
        print("0) Exit")
        choice = input("Enter option: ").strip()
        configs=[]
        if choice=="0":
            break
        elif choice=="1":
            print("[bold cyan]Enter configs line by line. Ctrl+D when done:[/bold cyan]")
            while True:
                try:
                    line=input()
                    if line.strip():
                        configs.append(line.strip())
                except EOFError:
                    break
        elif choice=="2":
            print("[bold cyan]Enter subscription links line by line. Ctrl+D when done:[/bold cyan]")
            while True:
                try:
                    line=input().strip()
                    if line:
                        try:
                            r=requests.get(line, timeout=5)
                            text=r.text.strip()
                            for l in text.splitlines():
                                if l.strip():
                                    configs.append(l.strip())
                        except Exception:
                            print(f"[bold red]Failed to fetch link:[/bold red] {line}")
                except EOFError:
                    break
        else:
            print("[bold red]Invalid input method![/bold red]")
            continue

        if not configs:
            print("[bold red]No configs entered![/bold red]")
            continue

        ping_results={}
        parsed_list=[]
        for conf in configs:
            parsed=parse_config(conf)
            proto=parsed.get("protocol","unknown")
            ping=ping_host(parsed.get("host","0.0.0.0"))
            status,label=classify_ping(ping)
            ping_results[conf]=(status,ping)
            parsed_list.append(parsed)
            print(f"[bold cyan]{proto.upper()}[/bold cyan] {parsed['remark']} -> {label} | {ping if ping else 'NO REPLY'} ms")

        while True:
            print("\n[cyan]Select output:[/cyan]")
            print("1) Fragment V1")
            print("2) Fragment V2")
            print("3) Combo-2")
            print("4) Combo-3")
            print("5) Generate fragments for only EXCELLENT/GOOD V2")
            print("9) Re-run probe & parse")
            print("0) Back to main menu / new inputs")
            out_choice = input("Enter option: ").strip()
            if out_choice=="0":
                break
            elif out_choice=="1":
                fragments=[build_fragment_v1(p, ping_results) for p in parsed_list]
                filename=Prompt.ask("Enter output filename")
                filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.json")
                with open(filepath,"w",encoding="utf-8") as f:
                    json.dump(fragments,f,ensure_ascii=False,indent=2)
                print(f"[bold green]Saved:[/bold green] {filepath}")
            elif out_choice=="2":
                fragments=[build_fragment_v2(p, ping_results) for p in parsed_list]
                filename=Prompt.ask("Enter output filename")
                filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.json")
                with open(filepath,"w",encoding="utf-8") as f:
                    json.dump(fragments,f,ensure_ascii=False,indent=2)
                print(f"[bold green]Saved:[/bold green] {filepath}")
            elif out_choice=="3":
                combos=generate_combo2(configs, cap=200)
                filename=Prompt.ask("Enter output filename")
                filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.txt")
                with open(filepath,"w",encoding="utf-8") as f:
                    f.write("\n".join(combos))
                print(f"[bold green]Saved ({len(combos)} combos):[/bold green] {filepath}")
            elif out_choice=="4":
                combos=generate_combo3(configs, cap=200)
                filename=Prompt.ask("Enter output filename")
                filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.txt")
                with open(filepath,"w",encoding="utf-8") as f:
                    f.write("\n".join(combos))
                print(f"[bold green]Saved ({len(combos)} combos):[/bold green] {filepath}")
            elif out_choice=="5":
                good_parsed=[p for p in parsed_list if classify_ping(ping_host(p.get("host","0.0.0.0")))[0]=="good"]
                fragments=[build_fragment_v2(p, ping_results) for p in good_parsed]
                filename=Prompt.ask("Enter output filename")
                filepath=os.path.join(OUTPUT_FOLDER,f"{filename}.json")
                with open(filepath,"w",encoding="utf-8") as f:
                    json.dump(fragments,f,ensure_ascii=False,indent=2)
                print(f"[bold green]Saved ({len(fragments)} V2 fragments):[/bold green] {filepath}")
            elif out_choice=="9":
                break
            else:
                print("[bold red]Invalid option![/bold red]")

if __name__=="__main__":
    main()