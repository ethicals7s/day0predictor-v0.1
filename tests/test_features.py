from day0predict.features import featurize_cve, to_feature_dict

def test_featurize_minimal():
    cve = {
        "cve": {
            "id": "CVE-2099-0001",
            "descriptions": [{"lang": "en", "value": "Remote code execution in foo"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "CHANGED",
                    }
                }]
            },
            "weaknesses": [{"description":[{"lang":"en","value":"CWE-94"}]}]
        }
    }
    row = featurize_cve(cve)
    feats = to_feature_dict(row)
    assert row.cve_id == "CVE-2099-0001"
    assert feats["base_score"] == 9.8
    assert feats["attack_vector_network"] == 1.0
    assert feats["keyword_rce"] == 1.0
