from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

_RCE_WORDS = re.compile(r"\b(remote code execution|rce|arbitrary code|execute code)\b", re.I)
_PRIVESC_WORDS = re.compile(r"\b(privilege escalation|privesc)\b", re.I)
_AUTH_BYPASS = re.compile(r"\b(authentication bypass|auth bypass)\b", re.I)
_SSRF = re.compile(r"\b(ssrf|server-side request forgery)\b", re.I)
_SQLI = re.compile(r"\b(sql injection|sqli)\b", re.I)
_XSS = re.compile(r"\b(cross-site scripting|xss)\b", re.I)
_DESER = re.compile(r"\b(deserialization|insecure deserialization)\b", re.I)
_TRAVERSAL = re.compile(r"\b(path traversal|directory traversal)\b", re.I)

def _safe_get(d: Dict[str, Any], path: List[str], default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

def extract_text_fields(cve: Dict[str, Any]) -> str:
    descs = _safe_get(cve, ["cve", "descriptions"], []) or []
    vals = []
    for item in descs:
        if isinstance(item, dict) and item.get("value"):
            vals.append(str(item["value"]))
    return " ".join(vals)

def extract_cvss_v31(cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    metrics = _safe_get(cve, ["cve", "metrics"], {}) or {}
    v31 = metrics.get("cvssMetricV31")
    if isinstance(v31, list) and v31:
        return v31[0]
    return None

@dataclass(frozen=True)
class FeatureRow:
    cve_id: str
    base_score: float
    attack_vector_network: int
    attack_complexity_low: int
    privileges_required_none: int
    user_interaction_none: int
    scope_changed: int
    cwe_present: int
    keyword_rce: int
    keyword_privesc: int
    keyword_auth_bypass: int
    keyword_ssrf: int
    keyword_sqli: int
    keyword_xss: int
    keyword_deser: int
    keyword_traversal: int

def featurize_cve(cve: Dict[str, Any]) -> FeatureRow:
    cve_id = _safe_get(cve, ["cve", "id"], "") or ""

    text = extract_text_fields(cve)
    m = extract_cvss_v31(cve)
    cvss = (m or {}).get("cvssData", {}) if isinstance(m, dict) else {}
    base_score = float(cvss.get("baseScore", 0.0) or 0.0)

    av = (cvss.get("attackVector") or "").upper()
    ac = (cvss.get("attackComplexity") or "").upper()
    pr = (cvss.get("privilegesRequired") or "").upper()
    ui = (cvss.get("userInteraction") or "").upper()
    scope = (cvss.get("scope") or "").upper()

    weaknesses = _safe_get(cve, ["cve", "weaknesses"], []) or []
    cwe_present = 1 if weaknesses else 0

    return FeatureRow(
        cve_id=cve_id,
        base_score=base_score,
        attack_vector_network=1 if av == "NETWORK" else 0,
        attack_complexity_low=1 if ac == "LOW" else 0,
        privileges_required_none=1 if pr == "NONE" else 0,
        user_interaction_none=1 if ui == "NONE" else 0,
        scope_changed=1 if scope == "CHANGED" else 0,
        cwe_present=cwe_present,
        keyword_rce=1 if _RCE_WORDS.search(text) else 0,
        keyword_privesc=1 if _PRIVESC_WORDS.search(text) else 0,
        keyword_auth_bypass=1 if _AUTH_BYPASS.search(text) else 0,
        keyword_ssrf=1 if _SSRF.search(text) else 0,
        keyword_sqli=1 if _SQLI.search(text) else 0,
        keyword_xss=1 if _XSS.search(text) else 0,
        keyword_deser=1 if _DESER.search(text) else 0,
        keyword_traversal=1 if _TRAVERSAL.search(text) else 0,
    )

def to_feature_dict(row: FeatureRow) -> Dict[str, float]:
    d = row.__dict__.copy()
    d.pop("cve_id", None)
    return {k: float(v) for k, v in d.items()}
