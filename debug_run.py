import subprocess
import sys

res = subprocess.run([sys.executable, 'detection_engine/benchmark.py'], capture_output=True, text=True, encoding='utf-8', errors='replace')
with open('full_err.txt', 'w', encoding='utf-8') as f:
    f.write(res.stdout)
    f.write("\n--- STDERR ---\n")
    f.write(res.stderr)
