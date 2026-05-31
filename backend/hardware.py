"""
NECROS X – Simulated API Discovery Engine.
In production this is replaced by a real packet sniffer on the appliance.
"""
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

BANKING_API_TEMPLATES = [
    {"path": "/upi/pay", "method": "POST", "category": "payments"},
    {"path": "/upi/verify", "method": "POST", "category": "payments"},
    {"path": "/kyc/verify", "method": "POST", "category": "kyc"},
    {"path": "/aadhaar/auth", "method": "POST", "category": "kyc"},
    {"path": "/loan/eligibility", "method": "GET", "category": "loans"},
    {"path": "/loan/apply", "method": "POST", "category": "loans"},
    {"path": "/account/balance", "method": "GET", "category": "accounts"},
    {"path": "/account/statement", "method": "GET", "category": "accounts"},
    {"path": "/cards/activate", "method": "POST", "category": "cards"},
    {"path": "/cards/block", "method": "POST", "category": "cards"},
    {"path": "/atm/switch", "method": "POST", "category": "atm"},
    {"path": "/swift/legacy", "method": "POST", "category": "swift"},
    {"path": "/swift/mt103", "method": "POST", "category": "swift"},
    {"path": "/v1/loan/eligibility", "method": "GET", "category": "deprecated"},
    {"path": "/v1/kyc/verify", "method": "POST", "category": "deprecated"},
    {"path": "/legacy/transfer", "method": "POST", "category": "deprecated"},
    {"path": "/soap/payments", "method": "POST", "category": "deprecated"},
    {"path": "/admin/debug", "method": "GET", "category": "internal"},
    {"path": "/shadow/kyc", "method": "POST", "category": "shadow"},
    {"path": "/orphan/report", "method": "GET", "category": "orphaned"},
    {"path": "/test/echo", "method": "POST", "category": "testing"},
]

def simulate_api_discovery(base_url: str) -> List[Dict[str, Any]]:
    discovered = []
    now = datetime.utcnow()
    selected = random.sample(BANKING_API_TEMPLATES, k=random.randint(12, 20))
    for i, template in enumerate(selected):
        days_old = random.randint(30, 2000)
        created = now - timedelta(days=days_old)
        last_used = now - timedelta(days=random.randint(1, max(2, days_old-10)))
        inactivity_days = (now - last_used).days
        auth_enabled = random.choice([True, False])
        if days_old > 600 and inactivity_days > 180 and not auth_enabled:
            prelim = "zombie"
        elif days_old > 400 and inactivity_days > 90:
            prelim = "orphaned"
        elif template["category"] == "deprecated" or "v1" in template["path"]:
            prelim = "deprecated"
        else:
            prelim = "active"
        endpoint = {
            "id": f"api-{i+1}-{random.randint(1000,9999)}",
            "base_url": base_url.rstrip("/"),
            "path": template["path"],
            "method": template["method"],
            "full_url": f"{base_url.rstrip('/')}{template['path']}",
            "category": template["category"],
            "owner": random.choice(["Payments Team", "KYC Squad", "Loan Dept", "Digital", "Core", "Unknown"]),
            "created_at": created.isoformat(),
            "last_used": last_used.isoformat(),
            "inactivity_days": inactivity_days,
            "auth_enabled": auth_enabled,
            "response_latency_ms": random.randint(20, 1200),
            "error_frequency": round(random.uniform(0, 0.4), 2),
            "deprecated_version_score": 1.0 if template["category"] == "deprecated" else 0.0,
            "public_exposure_level": random.randint(0, 3),
            "sensitive_data_access_score": round(random.uniform(0.2, 1.0), 2),
            "traffic_inactivity_score": min(1.0, inactivity_days / 365),
            "preliminary_status": prelim,
            "risk_score": 0,
            "lifecycle": prelim,
            "zombie_probability": 0.0,
            "confidence": 0.0,
            "isolated": False,
            "is_honeypot": False
        }
        discovered.append(endpoint)
    return discovered