from __future__ import annotations

import json
from pathlib import Path
from typing import Set

import pandas as pd


def load_kev_ids(path: Path) -> Set[str]:
    kev = json.loads(path.read_text(encoding="utf-8"))
    vulns = kev.get("vulnerabilities", []) or []
    ids = set()
    for v in vulns:
        cve = v.get("cveID") or v.get("cveId")
        if cve:
            ids.add(str(cve).strip())
    return ids


def main():
    kev_path = Path("data/kev.json")
    epss_path = Path("data/epss.csv")

    if not kev_path.exists():
        raise SystemExit("Missing data/kev.json. Run: python scripts/fetch_kev.py")
    if not epss_path.exists():
        raise SystemExit("Missing data/epss.csv. Run: python scripts/fetch_nvd.py")

    kev_ids = load_kev_ids(kev_path)

    epss = pd.read_csv(epss_path, low_memory=False)
    epss.columns = [c.strip().lower() for c in epss.columns]

    print("Detected EPSS columns:", list(epss.columns))

    # ---- Normalize EPSS column names (handle ALL known variants) ----
    rename_map = {}

    if "cve_id" in epss.columns:
        rename_map["cve_id"] = "cve"
    if "cve" not in epss.columns and "cve_id" not in rename_map.values():
        raise SystemExit("Could not find CVE column in EPSS CSV")

    if "epss" not in epss.columns:
        if "epss_score" in epss.columns:
            rename_map["epss_score"] = "epss"
        elif "score" in epss.columns:
            rename_map["score"] = "epss"

    if "percentile" not in epss.columns:
        if "epss_percentile" in epss.columns:
            rename_map["epss_percentile"] = "percentile"

    if rename_map:
        epss = epss.rename(columns=rename_map)

    required = {"cve", "epss"}
    missing = required - set(epss.columns)
    if missing:
        raise SystemExit(f"EPSS CSV missing required columns after normalization: {sorted(missing)}")

    if "percentile" not in epss.columns:
        epss["percentile"] = 0.0

    epss["cve"] = epss["cve"].astype(str).str.strip()
    epss["label"] = epss["cve"].isin(kev_ids).astype(int)

    df_pos = epss[epss["label"] == 1].copy()
    df_neg = epss[epss["label"] == 0].copy()

    positives = len(df_pos)
    if positives == 0:
        raise SystemExit("No KEV CVEs matched EPSS — this should not happen.")

    neg_target = min(len(df_neg), max(positives * 5, 1000))
    df_neg_sample = df_neg.sample(n=neg_target, random_state=42)

    out_df = pd.concat([df_pos, df_neg_sample], ignore_index=True)
    out_df = out_df.rename(columns={"cve": "cve_id"})

    out_df["epss"] = pd.to_numeric(out_df["epss"], errors="coerce").fillna(0.0)
    out_df["percentile"] = pd.to_numeric(out_df["percentile"], errors="coerce").fillna(0.0)

    out_df["epss_ge_001"] = (out_df["epss"] >= 0.01).astype(int)
    out_df["epss_ge_010"] = (out_df["epss"] >= 0.10).astype(int)
    out_df["epss_ge_050"] = (out_df["epss"] >= 0.50).astype(int)

    keep_cols = [
        "cve_id",
        "label",
        "epss",
        "percentile",
        "epss_ge_001",
        "epss_ge_010",
        "epss_ge_050",
    ]
    out_df = out_df[keep_cols]

    out = Path("data/dataset.csv")
    out_df.to_csv(out, index=False)

    print(
        f"Wrote {out} rows={len(out_df)} "
        f"positives={int(out_df['label'].sum())} negatives={int((out_df['label']==0).sum())}"
    )


if __name__ == "__main__":
    main()
