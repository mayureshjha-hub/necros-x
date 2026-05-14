"""
NECROS X — AI Zombie Prediction Engine
GradientBoosting ML trained on 8 features.
Predicts zombie probability at 30/60/90-day horizons.
"""

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

TRAINING_X = np.array([
    [0,    412, 0, 0, 3, 2, 800, 0.98],
    [0,    580, 0, 0, 4, 3, 900, 1.00],
    [2,    300, 0, 0, 3, 1, 600, 0.95],
    [5,    180, 0, 1, 2, 1, 400, 0.90],
    [0,    240, 1, 0, 2, 1, 500, 0.97],
    [1,    200, 0, 0, 3, 2, 700, 0.96],
    [0,    365, 0, 0, 4, 3, 800, 1.00],
    [3,    150, 0, 1, 2, 1, 350, 0.88],
    [0,    270, 0, 0, 3, 2, 600, 0.99],
    [8,     95, 1, 0, 2, 1, 300, 0.82],
    [12,    60, 1, 0, 2, 1, 200, 0.70],
    [25,    30, 1, 1, 1, 2, 150, 0.55],
    [50,    20, 1, 0, 2, 1, 180, 0.40],
    [100,    7, 1, 1, 1, 2, 100, 0.20],
    [30,    45, 0, 1, 2, 2, 250, 0.50],
    [15,    55, 1, 0, 3, 1, 300, 0.65],
    [200,   10, 1, 1, 1, 1,  90, 0.10],
    [80,    15, 1, 1, 1, 2, 120, 0.18],
    [8420,   1, 1, 1, 1, 1,  90, 0.00],
    [5100,   3, 1, 1, 1, 2, 120, 0.00],
    [2300,   0, 1, 1, 1, 1,  60, 0.00],
    [12000,  5, 1, 1, 1, 1, 180, 0.00],
    [9800,   2, 1, 1, 1, 1, 150, 0.00],
    [440,    7, 1, 1, 2, 1, 200, 0.00],
    [1200,   4, 1, 1, 1, 2,  90, 0.01],
    [3400,   1, 1, 1, 1, 1, 120, 0.00],
    [560,    8, 1, 1, 2, 1, 300, 0.02],
    [890,    3, 1, 1, 1, 2, 180, 0.00],
    [2100,   6, 1, 1, 1, 1, 240, 0.01],
    [4500,   2, 1, 1, 1, 1, 150, 0.00],
])

TRAINING_Y = np.array([
    1,1,1,1,1,1,1,1,1,1,
    1,0,0,0,1,1,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0
])

LAYER_RISK = {
    "AUTH":4,"ADMIN":4,"DATA":2,
    "FINANCE":2,"EVENTS":2,"OPS":3,
}


class ZombiePredictor:
    def __init__(self):
        self.model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=100,learning_rate=0.1,
                max_depth=4,random_state=42)),
        ])
        self.trained = False
        self._train()

    def _train(self):
        try:
            self.model.fit(TRAINING_X, TRAINING_Y)
            self.trained = True
        except Exception as e:
            print(f"[ML] Training failed: {e}")

    def _features(self, api):
        calls   = api.get("calls_per_day", api.get("calls", 0))
        inact   = api.get("inactivity_days", api.get("days", 0))
        auth    = 1 if api.get("auth") else 0
        enc     = 1 if (api.get("enc") or
                        api.get("encrypted")) else 0
        layer   = LAYER_RISK.get(api.get("layer","DATA"), 2)
        methods = len(api.get("methods",["GET"]))
        age     = max(inact,30)+(
            0  if calls>100 else
            30 if calls>10  else
            90 if calls>0   else 180)
        drop    = (
            min(inact/500,1.0) if calls==0 and inact>60
            else 0.5 if calls<10 and inact>30
            else 0.1 if calls<100 else 0.0)
        return np.array([[calls,inact,auth,enc,
                          layer,methods,age,drop]])

    def predict(self, api):
        if not self.trained:
            return self._fallback(api)
        try:
            feat  = self._features(api)
            proba = self.model.predict_proba(feat)[0]
            prob  = float(proba[1])
            level = (
                "CRITICAL" if prob>=0.75 else
                "HIGH"     if prob>=0.50 else
                "MEDIUM"   if prob>=0.25 else "LOW")
            return {
                "zombie_probability":   round(prob*100,1),
                "risk_level":           level,
                "prediction_30d":       round(
                    self._project(api,30)*100,1),
                "prediction_60d":       round(
                    self._project(api,60)*100,1),
                "prediction_90d":       round(
                    self._project(api,90)*100,1),
                "confidence":           round(max(proba)*100,1),
                "contributing_factors": self._factors(api,prob),
                "recommendation":       self._recommend(prob),
                "predicted_zombie_date":self._date(prob),
                "model":                "GradientBoosting",
                "features_used":        8,
            }
        except Exception:
            return self._fallback(api)

    def _project(self, api, days):
        try:
            a2 = dict(api)
            a2["inactivity_days"] = (
                api.get("inactivity_days",
                        api.get("days",0)) + days)
            if a2["inactivity_days"] > 60:
                a2["calls_per_day"] = max(
                    api.get("calls_per_day",0)*0.7, 0)
            return float(
                self.model.predict_proba(
                    self._features(a2))[0][1])
        except Exception:
            base = api.get("inactivity_days",
                           api.get("days",0))
            return min((base+days)/500,1.0)

    def _factors(self, api, prob):
        calls = api.get("calls_per_day",api.get("calls",0))
        inact = api.get("inactivity_days",api.get("days",0))
        f = []
        if calls==0:
            f.append({"factor":"Zero daily calls",
                       "impact":"CRITICAL","weight":35})
        elif calls<10:
            f.append({"factor":f"Low usage ({calls}/day)",
                       "impact":"HIGH","weight":20})
        if inact>180:
            f.append({"factor":f"{inact}d inactive",
                       "impact":"CRITICAL","weight":30})
        elif inact>60:
            f.append({"factor":f"{inact}d inactive",
                       "impact":"HIGH","weight":15})
        if not api.get("auth"):
            f.append({"factor":"No authentication",
                       "impact":"HIGH","weight":20})
        if not (api.get("enc") or api.get("encrypted")):
            f.append({"factor":"No TLS",
                       "impact":"MEDIUM","weight":10})
        if api.get("layer","") in ("ADMIN","AUTH"):
            f.append({"factor":f"High-risk layer: {api.get('layer','')}",
                       "impact":"HIGH","weight":15})
        if not f:
            f.append({"factor":"API appears healthy",
                       "impact":"LOW","weight":0})
        return f

    def _recommend(self, prob):
        if prob>=0.75:
            return ("IMMEDIATE: Deploy honeypot, rotate credentials.")
        elif prob>=0.50:
            return ("HIGH PRIORITY: Security review within 48h.")
        elif prob>=0.25:
            return ("MONITOR: Add to watchlist, track usage.")
        return "HEALTHY: Continue standard monitoring."

    def _date(self, prob):
        if prob>=0.75: return "Already at zombie risk"
        if prob>=0.50: return "~30 days"
        if prob>=0.25: return "~90 days"
        return ">12 months"

    def _fallback(self, api):
        inact = api.get("inactivity_days",api.get("days",0))
        calls = api.get("calls_per_day",api.get("calls",0))
        s = 0.0
        if calls==0:  s+=0.40
        if inact>180: s+=0.30
        if not api.get("auth"): s+=0.20
        if inact>60:  s+=0.10
        s = min(s,1.0)
        return {
            "zombie_probability":   round(s*100,1),
            "risk_level":           (
                "CRITICAL" if s>=0.75 else
                "HIGH"     if s>=0.50 else
                "MEDIUM"   if s>=0.25 else "LOW"),
            "prediction_30d":       round(min(s*1.10,1)*100,1),
            "prediction_60d":       round(min(s*1.22,1)*100,1),
            "prediction_90d":       round(min(s*1.38,1)*100,1),
            "confidence":           70.0,
            "contributing_factors": [],
            "recommendation":       self._recommend(s),
            "predicted_zombie_date":self._date(s),
            "model":                "Rule-Based Fallback",
            "features_used":        4,
        }


_predictor = ZombiePredictor()

def predict_zombie(api):
    return _predictor.predict(api)

def predict_all(apis):
    results = []
    for api in apis:
        pred = _predictor.predict(api)
        results.append({
            "id":api.get("id",""),
            "path":api.get("path",""),
            "status":api.get("status",""),
            **pred,
        })
    return sorted(results,
                  key=lambda x:x["zombie_probability"],
                  reverse=True)