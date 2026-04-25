import os
import mmap
import time
import math
import zipfile
import re
import logging
import hashlib
import json
from typing import Optional

# --- Configuration ---
MAX_SCAN_SIZE = 100 * 1024 * 1024
RISK_THRESHOLD = 60
INTEL_DB = "aegis_intel.json"

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- Reputation Database ---
class ReputationDB:
    def __init__(self, path: str):
        self.path = path
        self.db = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def get(self, f_hash: str) -> Optional[dict]:
        return self.db.get(f_hash)

    def save(self, f_hash: str, status: str, score: int):
        self.db[f_hash] = {"status": status, "score": score, "ts": time.time()}
        try:
            with open(self.path, 'w') as f:
                json.dump(self.db, f)
        except:
            pass

# --- Scanner Engine ---
class ThreatScanner:
    def __init__(self):
        self.code_heuristics = {
            b'Landroid/telephony/SmsManager;->sendTextMessage': 45,
            b'Ljava/lang/Runtime;->exec': 30,
            b'Ldalvik/system/DexClassLoader': 35,
            b'Landroid/app/admin/DevicePolicyManager;': 50
        }

        self.perm_heuristics = {
            b'android.permission.SEND_SMS': 30,
            b'android.permission.RECEIVE_BOOT_COMPLETED': 20,
            b'android.permission.SYSTEM_ALERT_WINDOW': 25,
            b'android.permission.BIND_DEVICE_ADMIN': 50
        }

        self.sig_pattern = re.compile(b'|'.join(map(re.escape, self.code_heuristics.keys())))

    def scan_path(self, path: str, reputation_db: ReputationDB):
        score = 0
        reasons = []

        try:
            if not os.path.isfile(path):
                print("File not found.")
                return

            # Hash
            f_hash = self._calculate_hash(path)
            intel = reputation_db.get(f_hash)

            if intel:
                print(f"[DB HIT] Already scanned → Score: {intel['score']}")
                return

            size = os.path.getsize(path)
            if size > MAX_SCAN_SIZE:
                print("File too large, skipped.")
                return

            with open(path, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

                # Entropy
                entropy = self._get_max_entropy(mm, size)
                if entropy > 7.7:
                    score += 20
                    reasons.append(f"HIGH_ENTROPY({entropy:.2f})")

                # Code signatures
                matches = self.sig_pattern.findall(mm)
                for m in set(matches):
                    score += self.code_heuristics[m]
                    reasons.append(m.decode().split(';')[-1])

                mm.close()

            # APK scan
            if path.lower().endswith(".apk"):
                score += self._audit_apk(path, reasons)

            # Verdict
            status = "THREAT" if score >= RISK_THRESHOLD else "CLEAN"
            reputation_db.save(f_hash, status, score)

            print("\n--- SCAN RESULT ---")
            print("File:", path)
            print("Score:", score)
            print("Status:", status)
            print("Reasons:", reasons)
            print("-------------------\n")

        except Exception as e:
            print("Error:", e)

    def _calculate_hash(self, path: str) -> str:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    def _get_max_entropy(self, mm, size):
        offsets = [0, size//2, max(0, size-4096)]
        scores = []

        for off in offsets:
            chunk = mm[off:off+4096]
            if not chunk:
                continue

            counts = [0]*256
            for b in chunk:
                counts[b] += 1

            scores.append(-sum((c/len(chunk))*math.log2(c/len(chunk)) for c in counts if c))

        return max(scores, default=0)

    def _audit_apk(self, path: str, reasons: list) -> int:
        score = 0
        try:
            with zipfile.ZipFile(path) as apk:
                if 'AndroidManifest.xml' in apk.namelist():
                    manifest = apk.read('AndroidManifest.xml')
                    for perm, weight in self.perm_heuristics.items():
                        if perm in manifest:
                            score += weight
                            reasons.append(f"PERM:{perm.decode().split('.')[-1]}")
        except:
            pass
        return score

# --- MAIN MENU ---
if __name__ == "__main__":
    scanner = ThreatScanner()
    intel = ReputationDB(INTEL_DB)

    while True:
        print("\n1. Scan single file")
        print("2. Scan Download folder")
        print("3. Exit")

        choice = input("Choose option: ")

        if choice == "1":
            path = input("Enter file path: ")
            scanner.scan_path(path, intel)

        elif choice == "2":
            folder = "/storage/emulated/0/Download"
            for file in os.listdir(folder):
                scanner.scan_path(os.path.join(folder, file), intel)

        elif choice == "3":
            break
