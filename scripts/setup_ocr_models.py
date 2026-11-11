"""
OCR Model Setup Utility for Bharat Analyzer.
Downloads official Tesseract hin.traineddata and eng.traineddata from
tesseract-ocr/tessdata_fast into ./.workspace_tmp/tessdata/ for offline OCR execution.
"""

import os
from pathlib import Path
import sys
import urllib.request
import urllib.error


HIN_URL = "https://github.com/tesseract-ocr/tessdata_fast/raw/main/hin.traineddata"
ENG_URL = "https://github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata"


def setup_ocr_models(target_dir: str = "./.workspace_tmp/tessdata") -> bool:
    """Downloads Hindi and English traineddata models into target workspace directory."""
    dest = Path(target_dir)
    dest.mkdir(parents=True, exist_ok=True)

    models = [
        ("Hindi (hin.traineddata)", HIN_URL, dest / "hin.traineddata"),
        ("English (eng.traineddata)", ENG_URL, dest / "eng.traineddata"),
    ]

    all_successful = True
    print(f"[*] Setting up Bilingual OCR Models in: {dest.resolve()}")

    for name, url, out_path in models:
        if out_path.exists() and out_path.stat().st_size > 1024:
            print(f"[+] {name} already present at: {out_path} ({out_path.stat().st_size:,} bytes)")
            continue

        print(f"[>] Downloading {name} from {url} ...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BharatAnalyzer-Setup/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
                out_path.write_bytes(content)
            print(f"[SUCCESS] Saved {name} ({len(content):,} bytes).")
        except urllib.error.URLError as err:
            print(f"[WARNING] Network download failed for {name}: {err}")
            print(f"          In offline mode, pure-Python stream fallback will be utilized.")
            all_successful = False
        except Exception as exc:
            print(f"[ERROR] Failed to download {name}: {exc}")
            all_successful = False

    if all_successful:
        print("[*] Bilingual OCR setup complete. Tesseract models ready.")
    else:
        print("[!] Setup completed with warnings. Offline fallback remains fully operational.")

    return all_successful


if __name__ == "__main__":
    success = setup_ocr_models()
    sys.exit(0 if success else 1)
