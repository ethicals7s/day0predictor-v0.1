from __future__ import annotations

from pathlib import Path
import gzip
import requests

EPSS_GZ = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def main():
    out_csv = Path("data/epss.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    r = requests.get(EPSS_GZ, timeout=120)
    r.raise_for_status()

    text = gzip.decompress(r.content).decode("utf-8", errors="replace")

    # EPSS files often start with comment/metadata lines beginning with '#'
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise SystemExit("EPSS download produced no usable CSV lines (after removing comments).")

    out_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_csv} lines={len(lines)} first_line={lines[0][:80]}")


if __name__ == "__main__":
    main()
