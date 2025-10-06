# ==================== Imports ====================
import os
import re
import subprocess
import time
from urllib.parse import unquote
from rich import print
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== Settings ====================
OUTPUT_FOLDER = "/storage/emulated/0/Download/almasi98"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MAX_THREADS = 20
PING3_COUNT = 3  # تعداد پینگ3 برای میانگین

# ==================== Helpers ====================
def extract_host(config: str):
    m = re.search(r"@([^:/?#\s]+)", config)
    if m:
        return m.group(1)
    m = re.search(r"://([^:/?#\s]+)", config)
    return m.group(1) if m else None

def extract_protocol(config: str):
    proto = config.split("://")[0].lower()
    return proto

# -------------------- Method 1: subprocess ping --------------------
def ping_subprocess(host: str):
    """Ping host using system ping command (Linux/Termux style)"""
    try:
        output = subprocess.check_output(
            ["ping", "-c", "3", "-W", "1", host],
            stderr=subprocess.DEVNULL
        ).decode()
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None
    except Exception:
        return None

# -------------------- Method 2: ping3 --------------------
def ping_ping3(host: str, count: int = PING3_COUNT):
    results = []
    for _ in range(count):
        try:
            result = ping(host, timeout=1, unit="ms")
            if result is not None:
                results.append(result)
        except Exception:
            continue
    if results:
        return sum(results) / len(results)
    return None

def classify_ping(avg_ms: float | None):
    if avg_ms is None:
        return "bad", "[bold red][BAD][/bold red]"
    if avg_ms < 150:
        return "good", "[bold green][GOOD][/bold green]"
    if avg_ms < 300:
        return "warn", "[bold yellow][WARN][/bold yellow]"
    return "bad", "[bold red][BAD][/bold red]"

# ==================== Input ====================
print("[cyan]Enter your configs line by line (any protocol). Ctrl+D when done:[/cyan]")
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

# ==================== Prepare Protocol Count ====================
protocol_count = {}
for cfg in configs:
    proto = extract_protocol(cfg)
    protocol_count[proto] = 0

# ==================== Ping + Stats with Progress ====================
results = []

def process_config(cfg: str):
    host = extract_host(cfg)
    if not host:
        return cfg, None, None, "ignored"
    sub_ms = ping_subprocess(host)
    ping3_ms = ping_ping3(host, count=PING3_COUNT)
    status_sub, _ = classify_ping(sub_ms)
    status_ping3, _ = classify_ping(ping3_ms)
    return cfg, sub_ms, ping3_ms, status_sub, status_ping3

start_time = time.time()
with Progress(
    SpinnerColumn(),
    "[progress.description]{task.description}",
    BarColumn(),
    "[progress.percentage]{task.percentage:>3.0f}%",
    TimeRemainingColumn(),
) as progress:
    task = progress.add_task("[cyan]Pinging hosts...", total=len(configs))
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_cfg = {executor.submit(process_config, cfg): cfg for cfg in configs}
        for future in as_completed(future_to_cfg):
            cfg, sub_ms, ping3_ms, status_sub, status_ping3 = future.result()
            proto = extract_protocol(cfg)

            if status_sub is None and status_ping3 is None:
                print(f"[bold yellow]Ignored (invalid):[/bold yellow] {cfg}")
                continue

            protocol_count[proto] = protocol_count.get(proto, 0) + 1
            results.append({
                "config": cfg,
                "protocol": proto,
                "subprocess_ms": sub_ms,
                "ping3_ms": ping3_ms,
                "subprocess_status": status_sub,
                "ping3_status": status_ping3
            })
            progress.update(task, advance=1)

# ==================== Summary Table ====================
table = Table(title="Configs Summary (Combined Ping)")
table.add_column("Config")
table.add_column("Protocol")
table.add_column("SubProc(ms)")
table.add_column("SubProc Status")
table.add_column("Ping3(ms)")
table.add_column("Ping3 Status")

for r in results:
    table.add_row(
        r["config"],
        r["protocol"].upper(),
        str(r["subprocess_ms"]) if r["subprocess_ms"] is not None else "-",
        r["subprocess_status"].upper() if r["subprocess_status"] else "-",
        str(r["ping3_ms"]) if r["ping3_ms"] is not None else "-",
        r["ping3_status"].upper() if r["ping3_status"] else "-"
    )

print(table)

# ==================== Protocol Summary ====================
proto_table = Table(title="Protocol Counts")
proto_table.add_column("Protocol")
proto_table.add_column("Count")
for proto, count in protocol_count.items():
    proto_table.add_row(proto.upper(), str(count))
print(proto_table)

elapsed = time.time() - start_time
print(f"[cyan]Elapsed time: {elapsed:.2f} seconds[/cyan]")