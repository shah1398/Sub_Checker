from pathlib import Path

# ---------- مسیر خروجی ثابت ----------
OUTPUT_DIR = Path("/sdcard/Download/almasi98")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------- پرسش نام فایل ----------
file_name = input("Enter output file name (without extension): ").strip()
base_name = file_name
extension = ".json"
FINAL_FILE = OUTPUT_DIR / f"{base_name}{extension}"
counter = 1
while FINAL_FILE.exists():
    FINAL_FILE = OUTPUT_DIR / f"{base_name}{counter}{extension}"
    counter += 1

# ---------- ایجاد فایل و نوشتن خط اول ----------
with open(FINAL_FILE, "w", encoding="utf-8") as f:
    f.write("[\n\n")  # خط اول [ و یک خط فاصله

print(f"File created: {FINAL_FILE}")
print("Enter JSON fragments (multi-line allowed). Press Enter after each, Ctrl+D when finished:")

first_entry = True  # برای مدیریت کاماها

try:
    while True:
        fragment_lines = []
        while True:
            try:
                line = input()
            except EOFError:
                # Ctrl+D زده شد → پایان ورودی‌ها
                break
            if line == "":
                break
            fragment_lines.append(line)

        if fragment_lines:
            fragment = "\n".join(fragment_lines)
            # نوشتن بلافاصله در فایل
            with open(FINAL_FILE, "a", encoding="utf-8") as f:
                if first_entry:
                    f.write(fragment + "\n\n")
                    first_entry = False
                else:
                    f.write(fragment + ",\n\n")

except EOFError:
    pass

# ---------- حذف کامای آخر و بستن آرایه ----------
with open(FINAL_FILE, "r+", encoding="utf-8") as f:
    lines = f.readlines()
    # حذف کامای آخر
    for i in reversed(range(len(lines))):
        if lines[i].strip().endswith(","):
            lines[i] = lines[i].rstrip(",\n") + "\n"
            break
    # اضافه کردن ] انتهایی با یک خط فاصله قبل
    lines.append("]\n")
    f.seek(0)
    f.truncate()
    f.writelines(lines)

print(f"\n✅ All fragments saved in: {FINAL_FILE}")

