import json
import sys
import re
import os
import random
from urllib.parse import parse_qs, unquote

GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

SAVE_PATH = "/storage/emulated/0/Download/Akbar98"

# ==================== Helper Functions ====================
def is_valid_uuid(uuid):
    return re.fullmatch(r'[0-9a-fA-F-]{36}', uuid) is not None

def detect_config_type(line):
    line = line.strip()
    if line.startswith("vless://"):
        return "vless"
    elif line.startswith("vmess://"):
        return "vmess"
    elif line.startswith("trojan://"):
        return "trojan"
    elif line.startswith("ss://"):
        return "shadowsocks"
    elif line.startswith("wg://") or line.startswith("wireguard://"):
        return "wireguard"
    try:
        js = json.loads(line)
        protocol = js.get("protocol", "").lower()
        if protocol == "vless":
            return "json_vless"
        elif protocol == "vmess":
            return "json_vmess"
        elif protocol == "trojan":
            return "json_trojan"
        elif protocol == "shadowsocks":
            return "json_shadowsocks"
        elif protocol == "wireguard":
            return "json_wireguard"
    except:
        pass
    return "unknown"

def convert_json_to_vless(js):
    try:
        cfg = json.loads(js)
        out = cfg.get("outbounds", [{}])[0]
        vnext = out.get("settings", {}).get("vnext", [{}])[0]
        user = vnext.get("users", [{}])[0]
        uuid = user.get("id", "")
        address = vnext.get("address", "")
        port = vnext.get("port", "")
        stream = out.get("streamSettings", {})
        net = stream.get("network", "tcp")
        sec = stream.get("security", "tls")
        sni = stream.get("tlsSettings", {}).get("serverName", "")
        path = ""
        if net == "ws":
            path = stream.get("wsSettings", {}).get("path", "")
        elif net == "grpc":
            path = stream.get("grpcSettings", {}).get("serviceName", "")
        if not (uuid and address and port and is_valid_uuid(uuid)):
            return None
        return f"vless://{uuid}@{address}:{port}?encryption=none&type={net}&security={sec}&sni={sni}&path={path}#{address}"
    except:
        return None

# ==================== Parsing & Fragment Functions ====================
def parse_link(link):
    link = link.strip()
    if not link.startswith("vless://"):
        return None, None
    try:
        main_part = link.split("://")[1]
        if "#" in main_part:
            main_part, remark = main_part.split("#", 1)
        else:
            remark = ""
        if "?" in main_part:
            addr_port, params = main_part.split("?", 1)
            query = parse_qs(params)
        else:
            addr_port = main_part
            query = {}
        if '@' in addr_port:
            user, host_port = addr_port.split("@", 1)
        else:
            user = ""
            host_port = addr_port
        if ':' in host_port:
            address, port = host_port.split(":", 1)
        else:
            address, port = host_port, "443"
        parsed = {
            "protocol": "vless",
            "address": address,
            "port": int(port) if port.isdigit() else 443,
            "id": user,
            "params": {k: v[0] for k, v in query.items()},
            "remark": unquote(remark),
            "raw": link,
            "user": user
        }
        return "vless", parsed
    except:
        return None, None

def build_fragment_list(configs):
    fragments = []
    for i, cfg in enumerate(configs):
        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": cfg["address"],
                    "port": cfg["port"],
                    "users": [{
                        "id": cfg["id"],
                        "encryption": cfg["params"].get("encryption", "none"),
                        "flow": cfg["params"].get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": cfg["params"].get("type", "ws"),
                "security": cfg["params"].get("security", "tls"),
                "sockopt": {"dialerProxy": "fragment"},
                "tlsSettings": {
                    "serverName": cfg["params"].get("sni", cfg["params"].get("host", cfg["address"])),
                    "fingerprint": cfg["params"].get("fp", "chrome"),
                    "alpn": cfg["params"].get("alpn", "").split(",") if "alpn" in cfg["params"] else ["http/1.1"]
                },
                "wsSettings": {
                    "path": cfg["params"].get("path", "/"),
                    "headers": {"Host": cfg["params"].get("host", cfg["address"])}
                }
            }
        }
        fragment = {
            "remarks": cfg["remark"] or f"💦 {i+1} - VLESS",
            "log": {"loglevel": "warning"},
            "dns": {
                "servers": [
                    {"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"},
                    {"address": "8.8.8.8", "domains": [f"full:{cfg['address']}"], "skipFallback": True}
                ],
                "queryStrategy": "UseIP",
                "tag": "dns"
            },
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth","udp": True,"userLevel": 8},
                 "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": True}, "tag": "socks-in"},
                {"port": 10853, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1","network": "tcp,udp","port": 53}, "tag": "dns-in"}
            ],
            "outbounds": [
                outbound,
                {"tag": "fragment", "protocol": "freedom",
                 "settings": {"fragment":{"packets":"tlshello","length":"100-200","interval":"1-1"},
                              "domainStrategy":"UseIPv4v6"}}
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
                    {"network": "tcp", "outboundTag": "proxy", "type": "field"}
                ]
            }
        }
        fragments.append(fragment)
    return fragments

# ===================== Fragment v2 =====================
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
        
  # ساخت outbound بسته به پروتکل
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

# ===================== Fragment v5 =====================
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

# ===================== Combo Generators (Updated) =====================
def strip_protocol(link: str) -> str:
    if "://" in link:
        return link.split("://",1)[1]
    return link

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
        A=configs[i]; B=configs[j]; C=configs[k]
        tail=strip_protocol(C)
        combo=f"{A}+{B}+ss//{tail}"
        if combo in seen:
            continue
        seen.add(combo)
        combos.append(combo)
        if len(combos)>=cap:
            break
    return combos

# ===================== Save Output =====================
def save_output(choice, detected):
    os.makedirs(SAVE_PATH, exist_ok=True)
    filename = input(GREEN + "Enter file name (without extension): " + RESET).strip()
    if not filename:
        print(YELLOW + "❌ Invalid file name." + RESET)
        return None
    extension = "txt"
    content = []

    if choice == "1":
        content = detected["vless"] + detected["json_vless"]
    elif choice == "2":
        content = detected["vmess"] + detected["json_vmess"]
    elif choice == "3":
        content = detected["shadowsocks"] + detected["json_shadowsocks"]
    elif choice == "4":
        content = detected["trojan"] + detected["json_trojan"]
    elif choice == "5":
        vless_links = detected["vless"] + detected["json_vless"]
        parsed_list = [parse_link(link)[1] for link in vless_links if parse_link(link)[1]]
        content = fragment_v2(parsed_list)
        extension = "json"
    elif choice == "6":
        vless_links = detected["vless"] + detected["json_vless"]
        parsed_list = [parse_link(link)[1] for link in vless_links if parse_link(link)[1]]
        content = fragment_v5(parsed_list)
        extension = "json"
    elif choice == "7":
        vless_links = detected["vless"] + detected["json_vless"]
        parsed_list = [parse_link(link)[1] for link in vless_links if parse_link(link)[1]]
        content = build_fragment_list(parsed_list)
        extension = "json"
    elif choice == "8":
        valid_configs = detected["vless"] + detected["json_vless"] + detected["vmess"] + detected["json_vmess"]
        content = generate_combo2(valid_configs)
    elif choice == "9":
        valid_configs = detected["vless"] + detected["json_vless"] + detected["vmess"] + detected["json_vmess"]
        content = generate_combo3(valid_configs)
    else:
        print(YELLOW + "❌ Invalid option." + RESET)
        return None

    result_path = os.path.join(SAVE_PATH, f"{filename}.{extension}")
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            if extension == "json":
                json.dump(content, f, ensure_ascii=False, indent=2)
            else:
                for item in content:
                    f.write(item + "\n")
        print(GREEN + f"✅ Saved: {result_path}" + RESET)
        return result_path
    except Exception as e:
        print(YELLOW + f"⚠️ Error writing file: {e}" + RESET)
        return None

# ===================== Main Program =====================
def main():
    print(BLUE + "Choose input method:" + RESET)
    print("1) Paste configs manually")
    print("2) Load configs from subscription file (full path)")
    input_method = input("Select input method (1 or 2): ").strip()

    if input_method == "1":
        print(BLUE + "Paste your configs (links or JSON), then press Enter and Ctrl+D:\n" + RESET)
        input_text = sys.stdin.read().strip()
        if not input_text:
            print(YELLOW + "No input detected." + RESET)
            return
        lines = [l.strip() for l in input_text.splitlines() if l.strip()]
    elif input_method == "2":
        file_path = input(GREEN + "Enter subscription file path: " + RESET).strip()
        if not os.path.isfile(file_path):
            print(YELLOW + "File not found." + RESET)
            return
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    else:
        print(YELLOW + "Invalid input method." + RESET)
        return

    detected = {key: [] for key in [
        "vless","vmess","trojan","shadowsocks","wireguard",
        "json_vless","json_vmess","json_trojan","json_shadowsocks","json_wireguard","unknown"
    ]}

    for line in lines:
        t = detect_config_type(line)
        if t.startswith("json_"):
            if t == "json_vless":
                conv = convert_json_to_vless(line)
                if conv:
                    detected["json_vless"].append(conv)
                else:
                    detected["unknown"].append(line)
            else:
                detected[t].append(line)
        else:
            detected[t].append(line)

    total_count = sum(len(v) for v in detected.values())
    print(BLUE + f"\nDetected configs: {total_count}" + RESET)
    for key in detected:
        print(f"  {key}: {len(detected[key])}")

    if total_count == 0:
        print(YELLOW + "No configs detected." + RESET)
        return

    while True:
        print(BLUE + "\nChoose output format (0 to exit):" + RESET)
        print("1) VLESS")
        print("2) VMess")
        print("3) Shadowsocks")
        print("4) Trojan")
        print("5) Fragment v2")
        print("6) Fragment v5")
        print("7) Fragmented VLESS JSON")
        print("8) Combo-2")
        print("9) Combo-3")
        choice = input("Option: ").strip()
        if choice == "0":
            print(GREEN + "Exiting." + RESET)
            break
        save_output(choice, detected)

if __name__ == "__main__":
    main()