#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import threading
import requests
import socket
import urllib.parse

NORMAL_OUT = "normal1560.txt"
FINAL_OUT = "final1560.txt"
COUNTRY_FILE = "countries.json"

# ============ منابع اصلی ============

LINK_PATH = [
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Afghanistan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Albania.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Argentina.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Armenia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Australia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Austria.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Bahrain.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Belarus.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Belgium.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Belize.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Bolivia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Brazil.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Bulgaria.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Cambodia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Canada.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/CentralAfricanRepublic.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Chile.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/China.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Colombia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/CostaRica.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Cyprus.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Czechia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Denmark.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Ecuador.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/EquatorialGuinea.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Estonia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Finland.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/France.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Georgia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Germany.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Greece.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Hungary.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Hysteria2.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Iceland.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/India.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Indonesia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Iran.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Iraq.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Ireland.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Israel.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Italy.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Japan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Kazakhstan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Laos.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Latvia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Lithuania.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Luxembourg.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Malaysia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Malta.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Mauritius.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Mexico.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Moldova.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Montenegro.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Namibia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Netherlands.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/NorthMacedonia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Norway.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Oman.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Panama.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Peru.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Philippines.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Poland.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Portugal.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Romania.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Russia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Samoa.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Seychelles.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/ShadowSocks.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/ShadowSocksR.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Singapore.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Slovakia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Slovenia.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/SouthAfrica.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/SouthKorea.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/SouthSudan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Spain.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Sweden.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Switzerland.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Taiwan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Thailand.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/TrinidadAndTobago.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Trojan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Tuic.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Turkey.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Turkmenistan.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/UAE.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/UK.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/USA.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Ukraine.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Vietnam.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Vless.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Vmess.txt",
    "https://raw.githubusercontent.com/tepo18/V2RayScrapeByCountry/main/output_configs/Wireguard.txt"
]

# ======================================================================

def fetch(url):
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            return [i.strip() for i in r.text.splitlines() if i.strip()]
    except:
        pass
    return []


def detect_protocol(line):
    l = line.lower()
    for p in ["vmess://", "vless://", "trojan://", "ss://", "ssr://",
              "hy2://", "hysteria2://", "tuic://", "wireguard://", "wg://", "socks://"]:
        if l.startswith(p):
            return p.replace("://", "")
    return "other"


def parse_host_port(link):
    try:
        # find host:port
        import re
        m = re.search(r"@([^:]+):(\d+)", link)
        if m:
            return m.group(1), int(m.group(2))
    except:
        pass
    return None, None


def tcp_test(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False


def process_country(country, lines):
    proto_map = {}

    for line in lines:
        proto = detect_protocol(line)
        proto_map.setdefault(proto, []).append(line)

    # خروجی نهایی متنی
    out = []

    for proto in sorted(proto_map.keys()):
        for line in proto_map[proto]:
            out.append(line)

    return out


def update_all():
    print("[*] Fetching all sources...")

    # load country list
    with open(COUNTRY_FILE, "r", encoding="utf-8") as f:
        country_order = json.load(f)

    COUNTRIES = {os.path.splitext(os.path.basename(url))[0]: url for url in LINK_PATH}

    all_normal = []
    all_final = []

    # مرتب‌سازی الفبایی کشورها
    for country in sorted(country_order):

        if country not in COUNTRIES:
            continue

        data = fetch(COUNTRIES[country])
        if not data:
            continue

        processed = process_country(country, data)

        all_normal.append(f"### {country}")
        all_normal.extend(processed)

        # تست نهایی
        final_ok = []
        for line in processed:
            host, port = parse_host_port(line)
            if host and port:
                if tcp_test(host, port):
                    final_ok.append(line)

        all_final.append(f"### {country}")
        all_final.extend(final_ok)

    # نوشتن خروجی‌ها
    with open(NORMAL_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(all_normal))

    with open(FINAL_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(all_final))

    print("[✔] DONE — updated final1560 & normal1560")


if __name__ == "__main__":
    update_all()
