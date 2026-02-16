import requests
import re
import sys
import time
import shutil
import logging
from pathlib import Path
from datetime import datetime, timedelta

try:
    import geoip2.database
except ImportError:
    print("❌ geoip2 library is not installed.")
    print("   Install command: pip install geoip2")
    sys.exit(1)

# ---------- UTF-8 console support ----------
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

# ================= CONFIG =================
SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"

CHECK_IP_MODE = "geo"          # Options: "geo" | "api" | None/False
SLEEP_BETWEEN_CHECKS = 0.7     # Delay only used in "api" mode

# Directories
DATA_DIR = Path("data")
OUTPUT_DIR = Path("output")

GEOIP_FILENAME = "GeoLite2-ASN.mmdb"
GEOIP_DATABASE_PATH = DATA_DIR / GEOIP_FILENAME

AUTO_DOWNLOAD_GEOIP = True
GEOIP_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb"

MIN_DB_SIZE = 1_500_000        # bytes - minimum valid database size
MAX_AGE_DAYS = 30              # warn if database is older than this

BAD_ASN_KEYWORDS = [
    "cloudflare", "fastly", "akamai", "cdn",
    "hetzner", "ovh", "digitalocean", "vultr", "linode",
    "contabo", "ionos", "scaleway", "oracle", "amazon aws",
    "google cloud", "microsoft azure"
]

ip_cache = {}

# Output files (numbered for natural sorting in file explorers)
FILES = {
    "stage1":    "2-reality_ok.txt",
    "final":     "1-valid_clean.txt",
    "isp_problem": "3-isp_suspect.txt",
    "rejected":  "4-invalid.txt"
}
# ==========================================

def ensure_directories():
    """Create data and output directories if they do not exist"""
    DATA_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

def extract_ip(link):
    """Extract IPv4 address from vless link"""
    match = re.match(r'vless://[^@]+@([^:/?#]+)', link)
    if match:
        host = match.group(1)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            return host
    return None

def quick_filter(link):
    """Stage 1 filter: must be vless + reality + not websocket"""
    link_lower = link.lower()
    if not link_lower.startswith("vless://"):
        return False
    if "security=reality" not in link_lower:
        return False
    if "type=ws" in link_lower:
        return False
    return True

def should_download_geoip():
    """Check if GeoLite2-ASN database needs to be downloaded or updated"""
    if not GEOIP_DATABASE_PATH.exists():
        return True

    size = GEOIP_DATABASE_PATH.stat().st_size
    if size < MIN_DB_SIZE:
        print(f"⚠ Existing file too small ({size:,} bytes) → will re-download")
        return True

    mod_time = datetime.fromtimestamp(GEOIP_DATABASE_PATH.stat().st_mtime)
    age = datetime.now() - mod_time

    if age > timedelta(days=MAX_AGE_DAYS):
        print(f"⚠ Database is old ({age.days} days old) → manual update recommended")
        return False  # Set to True if you want automatic update

    print(f"✓ GeoLite2-ASN database found (age: {age.days} days, size: {size:,} bytes)")
    return False

def download_geoip_database():
    """Download GeoLite2-ASN database if necessary"""
    if not should_download_geoip():
        return True

    print(f"⏳ Downloading GeoLite2-ASN database to {DATA_DIR} ...")
    try:
        with requests.get(GEOIP_URL, timeout=60, stream=True) as r:
            r.raise_for_status()
            with open(GEOIP_DATABASE_PATH, 'wb') as f:
                shutil.copyfileobj(r.raw, f)

        size = GEOIP_DATABASE_PATH.stat().st_size
        if size >= MIN_DB_SIZE:
            print(f"✅ Download successful – {GEOIP_FILENAME} saved in {DATA_DIR}")
            return True
        else:
            print(f"❌ Downloaded file too small ({size:,} bytes)")
            GEOIP_DATABASE_PATH.unlink(missing_ok=True)
            return False

    except Exception as e:
        print(f"❌ Download failed: {e}")
        GEOIP_DATABASE_PATH.unlink(missing_ok=True)
        return False

def check_ip_with_geoasn(ip):
    """Check if IP belongs to suspicious ASN/datacenter using GeoLite2-ASN"""
    if ip in ip_cache:
        return ip_cache[ip]

    if not GEOIP_DATABASE_PATH.exists():
        if AUTO_DOWNLOAD_GEOIP:
            if not download_geoip_database():
                ip_cache[ip] = "error"
                return "error"
        else:
            ip_cache[ip] = "no_db"
            return "no_db"

    try:
        with geoip2.database.Reader(str(GEOIP_DATABASE_PATH)) as reader:
            response = reader.asn(ip)
            org = (response.autonomous_system_organization or "").lower()
            asn_str = str(response.autonomous_system_number or "")

            is_bad = any(kw in org for kw in BAD_ASN_KEYWORDS) or any(kw in asn_str for kw in BAD_ASN_KEYWORDS)

            if is_bad:
                ip_cache[ip] = "bad"
                return "bad"
            else:
                ip_cache[ip] = "clean"
                return "clean"

    except geoip2.errors.AddressNotFoundError:  # type: ignore
        ip_cache[ip] = "unknown"
        return "unknown"
    except Exception as e:
        print(f"⚠ GeoASN error for {ip}: {e}")
        ip_cache[ip] = "error"
        return "error"

def save_file(key, data):
    """Save list of links to file in output directory"""
    filename = FILES[key]
    full_path = OUTPUT_DIR / filename
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            f.write("\n".join(data) + "\n")
        print(f"✔ Saved: {filename} → {len(data)} links in output/")
    except Exception as e:
        print(f"✘ Error saving {filename}: {e}")

def main():
    ensure_directories()

    print("Starting VLESS server check...\n")

    # Download list of links
    try:
        r = requests.get(SOURCE_URL, timeout=15)
        r.raise_for_status()
        links = [l.strip() for l in r.text.splitlines() if l.strip() and not l.strip().startswith('#')]
    except Exception as e:
        print(f"❌ Failed to download link list: {e}")
        return

    print(f"Received {len(links)} links")

    stage1_pass = []
    final_clean = []
    isp_problem = []
    rejected_stage1 = []

    # Stage 1: Quick filter
    for link in links:
        if quick_filter(link):
            stage1_pass.append(link)
        else:
            rejected_stage1.append(link)

    print(f"Stage 1 (Reality + no WS): {len(stage1_pass)} links passed")

    if CHECK_IP_MODE != "geo":
        print("IP checking disabled or unknown mode → only stage 1 applied")
        final_clean = stage1_pass[:]
    else:
        print("Starting IP check using GeoLite2-ASN...")
        download_geoip_database()  # Downloads only if needed

        for link in stage1_pass:
            ip = extract_ip(link)
            if not ip:
                isp_problem.append(link)
                continue

            status = check_ip_with_geoasn(ip)

            if status == "clean":
                final_clean.append(link)
                print(f"  ✅ OK   | {ip}")
            else:
                isp_problem.append(link)
                print(f"  ❌ BAD  | {ip} → {status}")

            # Sleep only when using external API (rate limit protection)
            if CHECK_IP_MODE == "api":
                time.sleep(SLEEP_BETWEEN_CHECKS)

    print("\n" + "═" * 60 + "\n")

    save_file("stage1", stage1_pass)
    save_file("final", final_clean)
    save_file("isp_problem", isp_problem)
    save_file("rejected", rejected_stage1)

    print("\nSummary:")
    print(f"  • Ready to use (clean): {len(final_clean)}")
    print(f"  • Suspicious ISP/datacenter: {len(isp_problem)}")
    print("Files saved in output/ folder, database stored in data/ folder.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    main()
