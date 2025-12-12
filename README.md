Day0Predictor 🛡️ (v0.1)

Early exploitation risk scoring for newly disclosed CVEs (defensive).

⚠️ This project does NOT predict unknown or undisclosed “true zero-day” vulnerabilities.
It estimates the likelihood that a newly disclosed CVE will be exploited in the wild, helping defenders prioritize patching and response.

🚨 Why this exists

Security teams face hundreds of new CVEs every week.
Most will never be exploited — a few will become incidents.

Day0Predictor helps answer:

“Which newly disclosed CVEs should I worry about first?”

It combines:

EPSS (industry-standard exploitation probability)

CISA Known Exploited Vulnerabilities (KEV) labels

A transparent ML model with explainable outputs

✨ What v0.1 does

Builds a dataset from:

EPSS exploitation scores

CISA KEV catalog (ground-truth exploitation)

Trains a logistic regression model (simple, explainable)

Outputs:

Risk score (0–100)

Feature-level reasons for the score

Provides a CLI tool for quick triage

🚀 Quick demo (recommended)

Score a well-known exploited vulnerability (Log4Shell):

python -m day0predict.cli score-epss \
  --cve-id CVE-2021-44228 \
  --model models/day0predict.joblib \
  --format json

Example output:

{
  "cve_id": "CVE-2021-44228",
  "risk": 98,
  "mode": "trained_model_epss",
  "features": {
    "epss": 0.94358,
    "percentile": 0.99957
  },
  "disclaimer": "Defensive risk scoring only. Uses EPSS-derived features."
}
📦 Installation
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -e .
🧪 Build the dataset & train
python scripts/fetch_kev.py
python scripts/fetch_nvd.py
python scripts/build_dataset.py
python scripts/train.py

This produces:

data/dataset.csv

models/day0predict.joblib

🖥️ CLI usage
EPSS-based scoring (recommended)
python -m day0predict.cli score-epss --cve-id CVE-2024-XXXX
CVE JSON scoring (fallback / demo)
python -m day0predict.cli score --file examples/cve_sample.json
🧠 Model notes

Optimized for early prioritization, not exploit prediction

Emphasizes precision over accuracy

Transparent coefficients → explainable decisions

No exploit code, payloads, or weaponization logic

🛑 Threat model & ethics

Audience

SOC teams

Vulnerability management

Blue teams

Non-goals

Discovering unknown vulnerabilities

Exploit development

Bypassing security controls

🗺️ Roadmap (v0.2+)

Time-based train/test split (prevent leakage)

Precision@K evaluation tables

Additional ecosystem features (package age, vendor)

Optional API (FastAPI)

CI re-enable with offline test fixtures

📜 License

MIT
