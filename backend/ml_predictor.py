"""
NECROS X – ML Predictor (GradientBoostingClassifier)
Trained on synthetic data, predicts lifecycle and risk.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from typing import Dict, Any, List
import random
from datetime import datetime

class APILifecycleClassifier:
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_names = [
            "endpoint_age_days", "auth_enabled", "response_latency_ms",
            "error_frequency", "traffic_inactivity_score", "deprecated_version_score",
            "public_exposure_level", "sensitive_data_access_score"
        ]
        self.lifecycle_classes = ["active", "deprecated", "orphaned", "zombie"]

    def generate_training_data(self, n_samples: int = 500) -> pd.DataFrame:
        data = []
        for _ in range(n_samples):
            age = random.randint(30, 2000)
            auth = random.choice([0, 1])
            lat = random.randint(20, 1200)
            err = round(random.uniform(0, 0.5), 2)
            inactivity = round(random.uniform(0, 1.0), 2)
            depr = random.choice([0.0, 1.0])
            exposure = random.randint(0, 3)
            sensitive = round(random.uniform(0, 1.0), 2)
            if age > 800 and inactivity > 0.7 and auth == 0 and depr > 0.5:
                label = "zombie"
            elif age > 500 and inactivity > 0.5:
                label = "orphaned"
            elif depr > 0.8 or age > 600:
                label = "deprecated"
            else:
                label = "active"
            data.append([age, auth, lat, err, inactivity, depr, exposure, sensitive, label])
        return pd.DataFrame(data, columns=self.feature_names + ["label"])

    def train(self):
        df = self.generate_training_data(500)
        X = df[self.feature_names]
        y = self.label_encoder.fit_transform(df["label"])
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        self.model = GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.1, max_depth=5, random_state=42
        )
        self.model.fit(X_train, y_train)
        print(f"[ML] Accuracy: {self.model.score(X_test, y_test):.2%}")

    def predict_lifecycle(self, api: Dict[str, Any]) -> Dict[str, Any]:
        if not self.model:
            self.train()
        feats = self._extract_features(api)
        X = np.array([feats])
        pred_idx = self.model.predict(X)[0]
        lifecycle = self.label_encoder.inverse_transform([pred_idx])[0]
        proba = self.model.predict_proba(X)[0]
        zombie_idx = list(self.label_encoder.classes_).index("zombie")
        zombie_prob = proba[zombie_idx]
        risk = min(100, int(
            zombie_prob * 50 +
            api.get("deprecated_version_score", 0) * 25 +
            api.get("traffic_inactivity_score", 0) * 15 +
            (api.get("public_exposure_level", 0) / 3) * 10
        ))
        return {
            "lifecycle": lifecycle,
            "zombie_probability": round(zombie_prob, 3),
            "confidence": round(max(proba), 3),
            "risk_score": risk,
            "prediction_time": datetime.utcnow().isoformat()
        }

    def forecast_risk(self, api: Dict[str, Any]) -> Dict[str, Any]:
        base = self.predict_lifecycle(api)
        inactivity = api.get("traffic_inactivity_score", 0)
        depr = api.get("deprecated_version_score", 0)
        cur = base["risk_score"]
        r30 = min(100, cur + int(round(inactivity * 12 + depr * 8)))
        r60 = min(100, r30 + int(round(inactivity * 8 + depr * 6)))
        r90 = min(100, r60 + int(round(inactivity * 6 + depr * 4)))
        return {
            "current_risk": cur,
            "risk_30d": r30,
            "risk_60d": r60,
            "risk_90d": r90,
            "forecast_time": datetime.utcnow().isoformat()
        }

    def _extract_features(self, api: Dict[str, Any]) -> List[float]:
        created = api.get("created_at", "")
        if created:
            age_days = (datetime.utcnow() - datetime.fromisoformat(created)).days
        else:
            age_days = api.get("inactivity_days", 200)
        return [
            float(age_days),
            float(api.get("auth_enabled", 0)),
            float(api.get("response_latency_ms", 100)),
            float(api.get("error_frequency", 0)),
            float(api.get("traffic_inactivity_score", 0)),
            float(api.get("deprecated_version_score", 0)),
            float(api.get("public_exposure_level", 0)),
            float(api.get("sensitive_data_access_score", 0))
        ]