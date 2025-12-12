# Day0Predictor 🛡️ (v0.1)

**Early exploitation risk scoring for newly disclosed vulnerabilities (defensive).**

> ⚠️ This project does **NOT** predict unknown or undisclosed “true zero-day” vulnerabilities.
> It estimates the **likelihood that a newly disclosed CVE will be exploited in the wild**, to help defenders prioritize triage and patching.

---

## What v0.1 does

* Builds a dataset from:

  * **NVD CVE data**
  * **CISA Known Exploited Vulnerabilities (KEV)** catalog (used as labels)
* Trains a **baseline logistic regression** model
* Scores a CVE with:

  * **Risk score (0–100)**
  * **Simple, transparent reason codes**
* Includes:

  * CLI tool
  * Tests
  * CI-ready structure

---

## Install (local)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -e .
pip install pytest
pytest
```

---

## Build the dataset

```bash
python scripts/fetch_kev.py
python scripts/fetch_nvd.py
python scripts/build_dataset.py
```

This creates:

```
data/dataset.csv
```

---

## Train the model

```bash
python scripts/train.py
```

Model artifact:

```
models/day0predict.joblib
```

---

## Score a CVE JSON record

Input must be a single CVE record (NVD-style JSON with a top-level `"cve"` object).

```bash
day0predict score --file path/to/cve.json
day0predict score --file path/to/cve.json --format json
```

Example output:

```
CVE-2025-XXXX risk=87/100
 - base_score: up
 - attack_vector_network: up
 - keyword_rce: up
```

---

## Metrics

For triage use-cases, precision matters more than accuracy.

```bash
python scripts/evaluate.py
```

Outputs:

* precision@25
* precision@50
* precision@100

---

## Threat model & ethics

* **Audience:** defenders, SOC teams, vulnerability management
* **Purpose:** prioritization & early risk assessment
* **Non-goals:** exploit development, weaponization, bypassing defenses

---

## Roadmap

* Time-based train/test split (avoid leakage)
* EPSS integration
* More textual + ecosystem features
* Better explainability
* Optional API + dashboard

---

## License

MIT
