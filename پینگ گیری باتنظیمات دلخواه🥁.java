#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
from pathlib import Path
from rich import print
from rich.table import Table
from ping3 import ping

# ==================== Default Settings ====================
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
Path(OUTPUT_FOLDER).mkdir(parents=True, exist_ok=True)

# تنظیمات پیش‌فرض، قابل تغییر از منوی تعاملی
VALID_PING_MIN = 1
VALID_PING_MAX = 1500
GOOD_THRESHOLD = 150
WARN_THRESHOLD = 300
TIMEOUT = 1
PING_COUNT = 3

# ==================== Helpers ====================
def extract_host(config: str):
    """Extract host from config line"""
    m = re.search(r"@([^:/?#\s]+)", config)
    if m:
        return m.group(1)
    m = re.search(r"://([^:/?#\s]+)", config)
    return m.group(1) if m else None

def ping_host_nonhost(host: str, count: int = PING_COUNT, timeout: int = TIMEOUT):
    """Ping host using ping3 and return average ms or None"""
    results = []
    for _ in range(count):
        try:
            r = ping(host, timeout=timeout, unit="ms")
            if r is not None:
                results.append(r)
        except Exception:
            continue
    if results:
        return sum(results)/len(results)
    return None

def classify_ping(avg_ms: float | None):
    """Return status string and colored label"""
    if avg_ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    if avg_ms < GOOD_THRESHOLD and VALID_PING_MIN <= avg_ms <= VALID_PING_MAX:
        return "good", "[bold green][GOOD][/bold green]"
    if avg_ms < WARN_THRESHOLD:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ==================== Input Configs ====================
print("[cyan]Enter your configs line by line (VLESS/Trojan/SS). Ctrl+D when done:[/cyan]")
configs = []
while True:
    try:
        line = input()
        if line.strip():
            configs.append(line.strip())
    except EOFError:
        break

if not configs:
    print("[bold red]No configs entered![/bold red]")
    exit()

# ==================== Interactive Settings Menu ====================
def settings_menu():
    global VALID_PING_MIN, VALID_PING_MAX, GOOD_THRESHOLD, WARN_THRESHOLD, TIMEOUT, PING_COUNT
    while True:
        print(f"""
[cyan]=== Settings Menu ===[/cyan]
1) Set valid ping range (current: {VALID_PING_MIN}-{VALID_PING_MAX} ms)
2) Set GOOD_THRESHOLD (current: {GOOD_THRESHOLD} ms)
3) Set WARN_THRESHOLD (current: {WARN_THRESHOLD} ms)
4) Set TIMEOUT (current: {TIMEOUT} s)
5) Set PING_COUNT (current: {PING_COUNT})
6) Start Ping
0) Exit
""")
        choice = input("Choice: ").strip()
        if choice == "1":
            mn = input(f"Enter min valid ping (current {VALID_PING_MIN}): ").strip()
            mx = input(f"Enter max valid ping (current {VALID_PING_MAX}): ").strip()
            if mn.isdigit() and mx.isdigit():
                VALID_PING_MIN, VALID_PING_MAX = int(mn), int(mx)
                print(f"[green]Saved: VALID_PING_MIN={VALID_PING_MIN}, VALID_PING_MAX={VALID_PING_MAX}[/green]")
        elif choice == "2":
            val = input(f"Enter GOOD_THRESHOLD (current {GOOD_THRESHOLD}): ").strip()
            if val.isdigit():
                GOOD_THRESHOLD = int(val)
                print(f"[green]Saved: GOOD_THRESHOLD={GOOD_THRESHOLD}[/green]")
        elif choice == "3":
            val = input(f"Enter WARN_THRESHOLD (current {WARN_THRESHOLD}): ").strip()
            if val.isdigit():
                WARN_THRESHOLD = int(val)
                print(f"[green]Saved: WARN_THRESHOLD={WARN_THRESHOLD}[/green]")
        elif choice == "4":
            val = input(f"Enter TIMEOUT in seconds (current {TIMEOUT}): ").strip()
            if val.isdigit():
                TIMEOUT = int(val)
                print(f"[green]Saved: TIMEOUT={TIMEOUT}[/green]")
        elif choice == "5":
            val = input(f"Enter PING_COUNT (current {PING_COUNT}): ").strip()
            if val.isdigit():
                PING_COUNT = int(val)
                print(f"[green]Saved: PING_COUNT={PING_COUNT}[/green]")
        elif choice == "6":
            break
        elif choice == "0":
            print("[cyan]Exiting...[/cyan]")
            exit()
        else:
            print("[red]Invalid choice[/red]")

settings_menu()

# ==================== Ping + Stats ====================
good, warn, bad = [], [], []
ping_results = {}
protocol_count = {"vless":0, "trojan":0, "ss":0, "ignored":0}

for cfg in configs:
    host = extract_host(cfg)
    if not host:
        protocol_count["ignored"] += 1
        print(f"[bold yellow]Ignored (invalid):[/bold yellow] {cfg}")
        continue
    ping_avg = ping_host_nonhost(host)
    status, label = classify_ping(ping_avg)
    ping_results[cfg] = (status, ping_avg)
    if status == "good":
        good.append(cfg)
    elif status == "warn":
        warn.append(cfg)
    else:
        bad.append(cfg)
    
    if cfg.startswith("vless://"):
        protocol_count["vless"] += 1
    elif cfg.startswith("trojan://"):
        protocol_count["trojan"] += 1
    elif cfg.startswith("ss://") or cfg.startswith("ssss://"):
        protocol_count["ss"] += 1

# ==================== Summary Table ====================
table = Table(title="Configs Summary")
table.add_column("Category")
table.add_column("Count")
table.add_row("Total configs", str(len(configs)))
table.add_row("Green (GOOD)", str(len(good)))
table.add_row("Yellow (WARN)", str(len(warn)))
table.add_row("Red (BAD)", str(len(bad)))
table.add_row("vless", str(protocol_count["vless"]))
table.add_row("trojan", str(protocol_count["trojan"]))
table.add_row("ss", str(protocol_count["ss"]))
table.add_row("Ignored/Invalid", str(protocol_count["ignored"]))
print(table)

# ==================== Output Menu ====================
def save_list_to_txt(lines, default_name):
    if not lines:
        print("[yellow]No items to save.[/yellow]")
        return
    fname = input(f"Enter filename (default: {default_name}.txt): ").strip() or default_name
    if not fname.endswith(".txt"):
        fname += ".txt"
    outpath = os.path.join(OUTPUT_FOLDER, fname)
    with open(outpath, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln.rstrip() + "\n")
    print(f"[green]Saved {len(lines)} items -> {outpath}[/green]")

while True:
    print("\n[cyan]Choose output to generate:[/cyan]")
    print("1) vless")
    print("2) trojan")
    print("3) ss/ssss")
    print("4) green (GOOD & in valid range)")
    print("5) green + yellow (GOOD + WARN)")
    print("6) all config")
    print("0) Exit")
    choice = input("Choice: ").strip()
    if choice == "0":
        print("[cyan]Exiting...[/cyan]")
        break
    elif choice == "1":
        save_list_to_txt([c for c in configs if c.startswith("vless://")], "vless")
    elif choice == "2":
        save_list_to_txt([c for c in configs if c.startswith("trojan://")], "trojan")
    elif choice == "3":
        save_list_to_txt([c for c in configs if c.startswith("ss://") or c.startswith("ssss://")], "ss")
    elif choice == "4":
        save_list_to_txt([c for c in good if VALID_PING_MIN <= (ping_results[c][1] or 0) <= VALID_PING_MAX], "green")
    elif choice == "5":
        save_list_to_txt([c for c in good+warn], "green_yellow")
    elif choice == "6":
        save_list_to_txt(configs, "all_configs")
    else:
        print("[red]Invalid choice[/red]")
