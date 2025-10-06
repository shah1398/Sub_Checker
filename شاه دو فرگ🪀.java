#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Fragment Builder v1.0
- Input: manual lines or subscription links (base64)
- Ping: subprocess ping + ping3 (average)
- Parse: vless, vmess (base64 json), trojan, ss (inline or base64)
- Build: produce full V2Ray/XRay fragment JSON objects per valid config
- Output: save JSON to /storage/emulated/0/Download/almasi98/<name>.json
"""

import os
import sys
import re
import time
import json
import base64
import subprocess
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party
try:
    from ping3 import ping
    from rich import print
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn
except Exception as e:
    print("[red]Missing dependencies.[/red] Please run: pip install ping3 rich")
    raise

# ---------------- Settings ----------------
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAX_THREADS = 20
PING3_COUNT = 3  # number of ping3 samples per host
PROTOCOL_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "grpc://", "shadowsocks://")

# ---------------- Helpers ----------------
def safe_b64decode(data: str) -> Optional[bytes]:
    if not isinstance(data, str):
        return None
    s = data.strip().replace("\n", "")
    # pad
    padding = (-len(s)) % 4
    s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        try:
            return base64.b64decode(s)
        except Exception:
            return None

def is_base64(s: str) -> bool:
    return safe_b64decode(s) is not None

def extract_host_from_link(link: str) -> Optional[str]:
    """
    Try to get host/ip from variety of link formats.
    """
    try:
        l = link.strip()
        # shadowsocks with inline user@host:port
        if l.startswith("ss://"):
            main = l[5:].split("#")[0]
            # sometimes main is base64 of "method:password@host:port"
            decoded = safe_b64decode(main)
            if decoded:
                try:
                    decoded_s = decoded.decode(errors="ignore")
                    if "@" in decoded_s:
                        return decoded_s.rsplit("@", 1)[1].split(":", 1)[0]
                except Exception:
                    pass
            # else try split on @
            if "@" in main:
                host_port = main.rsplit("@", 1)[1]
                return host_port.split(":", 1)[0]
        # vmess often is base64 of JSON — attempt to decode and find "add"
        if l.startswith("vmess://"):
            content = l.split("://",1)[1]
            maybe = safe_b64decode(content)
            if maybe:
                try:
                    jobj = json.loads(maybe.decode(errors="ignore"))
                    return jobj.get("add")
                except Exception:
                    pass
        # generic @host:port patterns
        m = re.search(r"@([^:/?#\s]+)", l)
        if m:
            return m.group(1)
        # fallback to scheme://host...
        m2 = re.search(r"://([^:/?#\s]+)", l)
        if m2:
            return m2.group(1)
    except Exception:
        pass
    return None

def extract_protocol(link: str) -> str:
    if "://" in link:
        return link.split("://",1)[0].lower()
    return "unknown"

# ---------------- Ping methods ----------------
def ping_subprocess_avg(host: str, count: int = 3, timeout_s: int = 1) -> Optional[float]:
    """
    Use system 'ping' command to ping host count times, return avg ms.
    Works on typical Linux/Android ping that outputs 'rtt min/avg/max/mdev = ...'
    """
    try:
        # -c count, -W timeout (per ping) ; timeout argument varies between systems
        output = subprocess.check_output(
            ["ping", "-c", str(count), "-W", str(timeout_s), host],
            stderr=subprocess.STDOUT,
            timeout=count * (timeout_s + 1)
        ).decode(errors="ignore")
        m = re.search(r"rtt .* = [\d.]+/([\d.]+)", output)
        if m:
            return float(m.group(1))
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    return None

def ping_ping3_avg(host: str, count: int = PING3_COUNT, timeout: float = 1.0) -> Optional[float]:
    """
    Use ping3 library (ICMP) to measure round-trip in milliseconds (unit="ms").
    """
    results = []
    for _ in range(count):
        try:
            r = ping(host, timeout=timeout, unit="ms")
            if r is not None:
                results.append(r)
        except Exception:
            pass
    if results:
        return sum(results) / len(results)
    return None

def classify_latency(ms: Optional[float]) -> Tuple[str, str]:
    """
    Classify latency:
      <150 ms -> good (green)
      <300 ms -> warn (yellow)
      None or >=300 -> bad (red)
    """
    if ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    try:
        val = float(ms)
    except Exception:
        return "bad", "[bold red][BAD][/bold red]"
    if val < 150:
        return "good", "[bold green][GOOD][/bold green]"
    if val < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ---------------- Parsers ----------------
def parse_vless(link: str) -> Optional[Dict[str, Any]]:
    """
    parse vless://<id>@host:port?param=...#remark
    returns dict with keys: protocol,address,port,id,user,params,remark,raw
    """
    try:
        main = link.split("://",1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
            remark = urllib.parse.unquote(remark)
        if "?" in main:
            addr_port, params = main.split("?",1)
            query = urllib.parse.parse_qs(params)
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
            "id": user_id,
            "user": user_id,
            "params": {k:v[0] for k,v in query.items()},
            "remark": remark or link
        }
    except Exception:
        return None

def parse_vmess(link: str) -> Optional[Dict[str, Any]]:
    """
    vmess://base64(json)
    The json contains keys like add/port/id/aid/net/type/host/path/tls
    """
    try:
        payload = link.split("://",1)[1].strip()
        data = safe_b64decode(payload)
        if not data:
            return None
        jobj = json.loads(data.decode(errors="ignore"))
        params = {}
        # normalize fields
        address = jobj.get("add") or jobj.get("server")
        port = int(jobj.get("port") or jobj.get("ps") or 0) or 443
        uuid = jobj.get("id") or jobj.get("uuid","")
        network = jobj.get("net") or jobj.get("type") or "tcp"
        # Build params similar to vless
        params["type"] = network
        if jobj.get("tls"):
            params["security"] = "tls"
        if jobj.get("host"):
            params["host"] = jobj.get("host")
        if jobj.get("path"):
            params["path"] = jobj.get("path")
        remark = jobj.get("ps") or link
        return {"protocol":"vmess","raw":link,"address":address,"port":port,"id":uuid,"user":uuid,"params":params,"remark":remark}
    except Exception:
        return None

def parse_trojan(link: str) -> Optional[Dict[str, Any]]:
    """
    trojan://password@host:port#remark
    """
    try:
        main = link.split("://",1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
            remark = urllib.parse.unquote(remark)
        if "@" in main:
            passwd, host_port = main.split("@",1)
        else:
            passwd = ""
            host_port = main
        if ":" in host_port:
            address, port = host_port.split(":",1)
        else:
            address = host_port
            port = "443"
        return {"protocol":"trojan","raw":link,"address":address,"port":int(port) if str(port).isdigit() else 443,"id":passwd,"user":passwd,"params":{},"remark":remark or link}
    except Exception:
        return None

def parse_ss(link: str) -> Optional[Dict[str, Any]]:
    """
    ss://method:pass@host:port#remark OR ss://base64(method:pass@host:port)#remark
    """
    try:
        main = link.split("://",1)[1]
        remark = ""
        if "#" in main:
            main, remark = main.split("#",1)
            remark = urllib.parse.unquote(remark)
        # If contains '@' directly
        if "@" in main and ":" in main.split("@",1)[1]:
            method_pass, host_port = main.split("@",1)
            if ":" in method_pass:
                method, password = method_pass.split(":",1)
            else:
                method, password = method_pass, ""
            if ":" in host_port:
                address, port = host_port.split(":",1)
            else:
                address, port = host_port, "443"
            return {"protocol":"ss","raw":link,"address":address,"port":int(port) if str(port).isdigit() else 443,"id":password,"user":password,"method":method,"params":{},"remark":remark or link}
        # else try base64 decode
        decoded = safe_b64decode(main)
        if decoded:
            s = decoded.decode(errors="ignore")
            if "@" in s:
                method_pass, host_port = s.split("@",1)
                if ":" in method_pass:
                    method, password = method_pass.split(":",1)
                else:
                    method, password = method_pass, ""
                if ":" in host_port:
                    address, port = host_port.split(":",1)
                else:
                    address, port = host_port, "443"
                return {"protocol":"ss","raw":link,"address":address,"port":int(port) if str(port).isdigit() else 443,"id":password,"user":password,"method":method,"params":{},"remark":remark or link}
    except Exception:
        pass
    return None

def parse_generic(link: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Try each parser to return normalized parsed dict and protocol name
    """
    link = link.strip()
    if not link:
        return None, None
    if link.startswith("vless://"):
        p = parse_vless(link)
        return ("vless", p) if p else (None, None)
    if link.startswith("vmess://"):
        p = parse_vmess(link)
        return ("vmess", p) if p else (None, None)
    if link.startswith("trojan://"):
        p = parse_trojan(link)
        return ("trojan", p) if p else (None, None)
    if link.startswith("ss://"):
        p = parse_ss(link)
        return ("ss", p) if p else (None, None)
    # fallback: try extracting address via regex
    m = re.search(r"://([^:/?#\s]+)", link)
    host = m.group(1) if m else None
    return ("unknown", {"protocol":"unknown","raw":link,"address":host,"port":443,"id":"","user":"","params":{},"remark":link}) if host else (None, None)

# ---------------- Fragment Builder (single robust builder) ----------------
def build_fragment_from_parsed(parsed: Dict[str, Any], ping_info: Optional[Tuple[str, Optional[float]]] = None) -> Optional[Dict[str, Any]]:
    """
    Given parsed dict, construct a complete, realistic V2Ray/XRay fragment object.
    This function tries to include all useful fields to make the fragment usable by V2Ray/XRay clients.
    """
    if not parsed:
        return None
    proto = parsed.get("protocol", "vless")
    address = parsed.get("address", "0.0.0.0")
    port = int(parsed.get("port") or 443)
    uid = parsed.get("id") or parsed.get("user") or ""
    params = parsed.get("params") or {}
    remark = parsed.get("remark") or parsed.get("raw") or f"{proto}_{address}"
    # ping info: (status, avg_ms)
    status = None
    avg_ms = None
    if ping_info:
        status, avg_ms = ping_info

    # decide network
    network = params.get("type") or params.get("net") or (params.get("network") if params.get("network") else None)
    # decide security
    security = params.get("security")
    if not security:
        if params.get("tls") in ("tls", "true", True, "1"):
            security = "tls"
        else:
            security = "none"

    # streamSettings default
    stream = {"network": (network or "ws"), "security": security, "sockopt": {"dialerProxy": "fragment"}}
    # TLS settings if needed
    if security in ("tls", "xtls"):
        stream["tlsSettings"] = {
            "serverName": params.get("sni") or params.get("host") or address,
            "fingerprint": params.get("fp", "chrome"),
            "alpn": [p.strip() for p in (params.get("alpn") or "").split(",") if p.strip()] or ["http/1.1"]
        }

    # network-specific settings
    net = stream["network"]
    if net == "ws":
        stream.setdefault("wsSettings", {"path": params.get("path", "/"), "headers": {"Host": params.get("host") or params.get("sni") or address}})
    elif net == "grpc":
        stream.setdefault("grpcSettings", {"serviceName": params.get("serviceName", ""), "multiMode": False})
    elif net == "h2":
        stream.setdefault("httpSettings", {"path": params.get("path", "/"), "host": [params.get("host", address)]})

    # Outbound builder depending on protocol
    if proto in ("vless", "vmess"):
        outbound = {
            "tag": "proxy",
            "protocol": proto,
            "settings": {
                "vnext": [
                    {
                        "address": address,
                        "port": port,
                        "users": [
                            {
                                "id": uid or "",
                                "encryption": params.get("encryption", "none"),
                                "flow": params.get("flow", "")
                            }
                        ]
                    }
                ]
            },
            "streamSettings": stream
        }
    elif proto == "trojan":
        outbound = {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {"servers": [{"address": address, "port": port, "password": uid or params.get("password","")}]},
            "streamSettings": stream
        }
    elif proto in ("ss", "shadowsocks"):
        method = parsed.get("method", params.get("method", "aes-128-gcm"))
        passwd = uid or params.get("password","")
        outbound = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": address, "port": port, "method": method, "password": passwd}]},
            "streamSettings": {"network": net if net else "tcp", "security": "none", "sockopt": {"dialerProxy": "fragment"}}
        }
    else:
        # fallback to freedom
        outbound = {"tag":"proxy","protocol":"freedom","settings":{}}

    # build full fragment object
    frag = {
        "remarks": remark,
        "log": {"loglevel": "warning", "access": "", "error": ""},
        "dns": {
            "servers": [
                {"address": "https://1.1.1.1/dns-query", "tag": "remote-dns"},
                "1.1.1.1",
                "8.8.8.8"
            ],
            "queryStrategy": "UseIP"
        },
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "tag": "socks-in",
                "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True}
            },
            {
                "port": 10853,
                "protocol": "dokodemo-door",
                "settings": {"address": "1.1.1.1", "network": "tcp,udp", "port": 53},
                "tag": "dns-in"
            }
        ],
        "outbounds": [
            outbound,
            {
                "tag": "fragment",
                "protocol": "freedom",
                "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-1"}, "domainStrategy": "UseIPv4v6"}
            },
            {"tag":"dns-out","protocol":"dns","settings":{}}
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                {"network": "tcp", "outboundTag": "proxy", "type": "field"},
                {"network": "udp", "outboundTag": "proxy", "type": "field"}
            ]
        },
        # extra metadata for debugging; will not break V2Ray but can be removed
        "meta": {"ping_status": status or "", "ping_ms": avg_ms if avg_ms is not None else ""}
    }

    return frag

# ---------------- Core flow: read inputs, ping, parse, build fragments ----------------
def fetch_subscriptions_interactive() -> List[str]:
    """
    Ask user for subscription URLs and fetch (assume base64 body contains configs lines)
    """
    import requests
    all_configs = []
    print("[cyan]Enter subscription URLs (empty to finish).[/cyan]")
    while True:
        url = input("Sub URL (enter to stop): ").strip()
        if not url:
            break
        try:
            r = requests.get(url, timeout=12)
            r.raise_for_status()
            text = r.text.strip()
            # try base64 decode whole body
            dec = safe_b64decode(text)
            if dec:
                payload = dec.decode(errors="ignore")
            else:
                payload = text
            lines = [ln.strip() for ln in payload.splitlines() if ln.strip()]
            # filter only recognized prefixes or base64 vmess lines
            for ln in lines:
                if any(ln.startswith(p) for p in PROTOCOL_PREFIXES) or ln.startswith("vmess://") or is_base64(ln):
                    all_configs.append(ln)
            print(f"[green]Fetched {len(lines)} lines, kept {len(all_configs)} so far[/green]")
        except Exception as e:
            print(f"[red]Failed to fetch {url}: {e}[/red]")
    return all_configs

def collect_inputs() -> List[str]:
    """
    Offer manual paste OR subscription fetch; returns list of raw config lines.
    """
    print("[cyan]Input mode:[/cyan]")
    print(" 1) Paste configs manually (line-by-line)")
    print(" 2) Fetch from subscription URLs (base64)")
    mode = input("Choose mode (1/2, default 1): ").strip() or "1"
    configs: List[str] = []
    if mode == "2":
        configs = fetch_subscriptions_interactive()
        if configs:
            print(f"[green]Total configs fetched: {len(configs)}[/green]")
    else:
        print("[cyan]Paste configs. Press Enter after each. When done press Ctrl+D (or Ctrl+Z on Windows) to finish input.[/cyan]")
        while True:
            try:
                line = input()
                if line and line.strip():
                    configs.append(line.strip())
            except EOFError:
                break
    # de-duplicate and strip
    unique = []
    seen = set()
    for c in configs:
        c2 = c.strip()
        if not c2:
            continue
        if c2 in seen:
            continue
        seen.add(c2)
        unique.append(c2)
    return unique

def process_pings_and_collect(configs: List[str]) -> Tuple[List[str], Dict[str, Tuple[str, Optional[float]]], Dict[str,int], List[Tuple[str,Dict[str,Any]]]]:
    """
    - For each config, extract host and run pings concurrently.
    - Returns:
        valid_configs_sorted: list of configs that passed (good/warn) or at least parsed
        ping_results: map config -> (status, avg_ms)
        protocol_count: counts per protocol
        parsed_entries: list of tuples (original_config, parsed_dict) for parsed ones
    """
    if not configs:
        return [], {}, {}, []

    ping_results: Dict[str, Tuple[str, Optional[float]]] = {}
    protocol_count: Dict[str,int] = {}
    parsed_entries: List[Tuple[str, Dict[str,Any]]] = []

    # helper for single config processing
    def work(cfg: str):
        host = extract_host_from_link(cfg)
        sub = None
        p3 = None
        if host:
            sub = ping_subprocess_avg(host, count=3, timeout_s=1)
            p3 = ping_ping3_avg(host, count=PING3_COUNT, timeout=1.0)
        status_sub, _ = classify_latency(sub)
        status_p3, _ = classify_latency(p3)
        # choose best available avg: prefer ping3
        avg = p3 if p3 is not None else sub
        # overall prefer good/warn from either
        overall = "bad"
        if status_p3 in ("good","warn"):
            overall = status_p3
        elif status_sub in ("good","warn"):
            overall = status_sub
        else:
            overall = "bad"
        return cfg, host, sub, p3, overall, avg

    # run concurrently
    with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn()) as prog:
        task = prog.add_task("[cyan]Pinging hosts...", total=len(configs))
        with ThreadPoolExecutor(max_workers=min(MAX_THREADS, max(2, len(configs)))) as exc:
            futures = {exc.submit(work, c): c for c in configs}
            for fut in as_completed(futures):
                cfg, host, sub, p3, overall, avg = fut.result()
                ping_results[cfg] = (overall, avg)
                proto = extract_protocol(cfg)
                protocol_count[proto] = protocol_count.get(proto, 0) + 1
                prog.update(task, advance=1)

    # parsing: try to parse those that at least have host or are known prefixes
    parsed_list: List[Tuple[str, Dict[str,Any]]] = []
    for cfg in configs:
        proto_name, parsed = parse_generic(cfg)
        if parsed:
            parsed_list.append((cfg, parsed))

    # build valid list: keep those that are good or warn (others still parsed but flagged bad)
    valid_configs = [c for c,(st,_) in ping_results.items() if st in ("good","warn")]
    # ensure dedup and sort: put good at top, then warn, then others
    ordered = []
    for s in ("good","warn","bad"):
        ordered.extend([c for c,(st,_) in ping_results.items() if st==s])
    # remove duplicates
    seen = set()
    ordered_unique = []
    for c in ordered:
        if c not in seen:
            ordered_unique.append(c); seen.add(c)

    return ordered_unique, ping_results, protocol_count, parsed_list

# ---------------- Save utilities ----------------
def ask_and_save_fragments(fragments: List[Dict[str,Any]], default_base: str = "fragment_output"):
    if not fragments:
        print("[yellow]No fragments to save.[/yellow]")
        return
    fname = input(f"Enter output filename (default: {default_base}.json): ").strip() or default_base
    if not fname.lower().endswith(".json"):
        fname = fname + ".json"
    outpath = os.path.join(OUTPUT_FOLDER, fname)
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(fragments, f, ensure_ascii=False, indent=2)
    print(f"[green]✅ Saved {len(fragments)} fragments -> {outpath}[/green]")

# ---------------- Main ----------------
def main():
    print("[bold cyan]Universal Fragment Builder[/bold cyan]")
    configs = collect_inputs()
    if not configs:
        print("[red]No configs provided. Exiting.[/red]")
        return

    print(f"[cyan]Collected {len(configs)} unique configs. Starting ping & parse...[/cyan]")
    ordered_configs, ping_results, protocol_count, parsed_list = process_pings_and_collect(configs)

    # Show summary table
    table = Table(title="Configs Summary")
    table.add_column("Config", overflow="fold")
    table.add_column("Protocol")
    table.add_column("Ping(ms)")
    table.add_column("Status")
    for cfg in ordered_configs:
        status, avg = ping_results.get(cfg, ("bad", None))
        avg_str = f"{avg:.2f}" if isinstance(avg, (int,float)) else "-"
        proto = extract_protocol(cfg).upper()
        table.add_row(cfg, proto, avg_str, status.upper())
    print(table)

    proto_table = Table(title="Protocol Counts")
    proto_table.add_column("Protocol")
    proto_table.add_column("Count")
    for proto, cnt in sorted(protocol_count.items(), key=lambda x: x[0]):
        proto_table.add_row(proto.upper(), str(cnt))
    print(proto_table)

    # Now build fragments for each parsed entry that is at least parsed and (optionally) ping good/warn
    fragments: List[Dict[str,Any]] = []
    for raw_cfg, parsed in parsed_list:
        # get ping info if available
        ping_info = ping_results.get(raw_cfg)  # (status, avg)
        # build fragment even if ping bad — user can decide; but we will only include if ping good/warn
        if ping_info and ping_info[0] in ("good", "warn"):
            frag = build_fragment_from_parsed(parsed, ping_info)
            if frag:
                fragments.append(frag)

    if not fragments:
        print("[yellow]No fragments generated (no parsed+live configs). You can still try generate from parsed ones regardless of ping.[/yellow]")
        # Ask user whether to generate fragments from parsed ignoring ping
        choice = input("Generate fragments from parsed configs regardless of ping? (y/N): ").strip().lower()
        if choice == "y":
            for raw_cfg, parsed in parsed_list:
                frag = build_fragment_from_parsed(parsed, ping_results.get(raw_cfg))
                if frag:
                    fragments.append(frag)
        else:
            print("[cyan]Exiting without saving fragments.[/cyan]")
            return

    # Save
    ask_and_save_fragments(fragments, default_base="almasi98_fragments")

    # Done
    print("[bold green]All done.[/bold green]")

if __name__ == "__main__":
    main()
