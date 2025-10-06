import os
from pathlib import Path

# ---------- Colors ----------
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# ---------- Fixed Output Directory ----------
OUTPUT_DIR = Path("/sdcard/Download/mix98")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------- Input Links ----------
print(f"{Colors.HEADER}📥 Paste your links (one per line). Press Enter after each. Press Ctrl+D when done:{Colors.ENDC}")

lines = []
try:
    while True:
        line = input()
        if line.strip():
            lines.append(line.strip())
except EOFError:
    pass  # Ctrl+D pressed → input finished

# ---------- Remove duplicates ----------
lines = list(dict.fromkeys(lines))

vless_links = [l for l in lines if l.startswith("vless://")]
trojan_links = [l for l in lines if l.startswith("trojan://")]
ss_links = [l for l in lines if l.startswith("ss://") or l.startswith("ssss://")]

lines_clean = vless_links + trojan_links + ss_links

if not lines_clean:
    print(f"{Colors.FAIL}❌ No valid links detected.{Colors.ENDC}")
    exit()

# ---------- Statistics ----------
def print_stats(vless, trojan, ss):
    total = len(vless) + len(trojan) + len(ss)
    print(f"{Colors.OKBLUE}\n================ Statistics ================\n{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'Protocol':<10} {'Count':>5}{Colors.ENDC}")
    print(f"{'VLESS':<10} {len(vless):>5}")
    print(f"{'Trojan':<10} {len(trojan):>5}")
    print(f"{'SS/SSS':<10} {len(ss):>5}")
    print(f"{'-'*20}")
    print(f"{'Total':<10} {total:>5}")
    print(f"{Colors.OKBLUE}============================================{Colors.ENDC}\n")

print_stats(vless_links, trojan_links, ss_links)

# ---------- Get folder name ----------
folder_name = input(f"{Colors.HEADER}Enter folder name to store split files: {Colors.ENDC}").strip()
output_path = OUTPUT_DIR / folder_name
output_path.mkdir(parents=True, exist_ok=True)

# ---------- Get batch size ----------
while True:
    try:
        batch_size = int(input(f"{Colors.HEADER}Enter number of configs per file: {Colors.ENDC}"))
        if batch_size <= 0:
            raise ValueError
        break
    except ValueError:
        print(f"{Colors.WARNING}⚠️ Please enter a valid positive number.{Colors.ENDC}")

# ---------- Split and Save ----------
total_links = len(lines_clean)
num_files = (total_links + batch_size - 1) // batch_size  # ceiling division

for i in range(num_files):
    start = i * batch_size
    end = min(start + batch_size, total_links)
    batch = lines_clean[start:end]
    file_name = f"input{i+1}.txt"
    file_path = output_path / file_name
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(batch))
    print(f"{Colors.OKGREEN}✅ Saved {len(batch)} configs to {file_name}{Colors.ENDC}")

print(f"{Colors.OKBLUE}\nAll files saved in folder: {output_path}{Colors.ENDC}")