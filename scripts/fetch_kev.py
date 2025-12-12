from __future__ import annotations

from pathlib import Path
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def main():
    out = Path("data/kev.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    out.write_text(r.text, encoding="utf-8")
    print(f"Wrote {out}")

if __name__ == "__main__":
    main()
