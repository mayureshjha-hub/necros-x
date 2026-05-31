
import os
import random
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from tinydb import TinyDB, Query as TinyQuery
import networkx as nx
import uvicorn

from hardware import simulate_api_discovery
from ml_predictor import APILifecycleClassifier

# ---------- Config ----------
SECRET_TOKEN = os.getenv("SECRET_TOKEN", "necros-secure-token-2024")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", None)

# ---------- Database ----------
class Database:
    def __init__(self, path):
        self.db = TinyDB(path)
    def all(self): return self.db.all()
    def get(self, cond): return self.db.get(cond)
    def insert(self, doc): return self.db.insert(doc)
    def update(self, fields, cond): return self.db.update(fields, cond)
    def truncate(self): self.db.truncate()
    def __len__(self): return len(self.db)

api_registry = Database("api_registry.json")
honeypot_events = Database("honeypot_events.json")

# ---------- Auth ----------
def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid token")
    if authorization.split(" ")[1] != SECRET_TOKEN:
        raise HTTPException(401, "Invalid token")
    return authorization.split(" ")[1]

# ---------- Models ----------
class ScanRequest(BaseModel):
    base_url: str = "https://api.examplebank.com"
class DefendRequest(BaseModel):
    target_api_ids: List[str] = []
class AIQuery(BaseModel):
    message: str

# ---------- App ----------
app = FastAPI(title="NECROS X", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ML classifier
ml = APILifecycleClassifier()

# ---------- Helpers ----------
def update_api_with_ml(api: dict) -> dict:
    pred = ml.predict_lifecycle(api)
    api.update({
        "lifecycle": pred["lifecycle"],
        "zombie_probability": pred["zombie_probability"],
        "confidence": pred["confidence"],
        "risk_score": pred["risk_score"]
    })
    return api

def build_attack_graph():
    G = nx.DiGraph()
    G.add_node("Internet", type="external")
    G.add_node("API Gateway", type="gateway")
    G.add_node("Core Banking DB", type="database", risk=80)
    G.add_node("KYC DB", type="database", risk=60)
    for api in api_registry.all():
        G.add_node(api["id"], type="api", **api)
        G.add_edge("API Gateway", api["id"])
        if "kyc" in api["path"] or "aadhaar" in api["path"]:
            G.add_edge(api["id"], "KYC DB", weight=api.get("risk_score",50)/100)
        if any(k in api["path"] for k in ["loan","account","transaction"]):
            G.add_edge(api["id"], "Core Banking DB", weight=api.get("risk_score",50)/100)
        if api.get("lifecycle") == "zombie" and api.get("risk_score",0) > 60:
            G.add_edge(api["id"], "Core Banking DB", weight=0.9, attack="exploit")
    G.add_edge("Internet", "API Gateway")
    nodes = [{"id": n, **G.nodes[n]} for n in G.nodes()]
    links = [{"source": u, "target": v, **G.edges[u,v]} for u,v in G.edges()]
    return {"nodes": nodes, "links": links}

# ---------- Startup ----------
@app.on_event("startup")
def startup():
    ml.train()
    if len(api_registry) == 0:
        seed = simulate_api_discovery("https://api.examplebank.com")
        for api in seed:
            api = update_api_with_ml(api)
            api_registry.insert(api)
    print(f"[STARTUP] Registry: {len(api_registry)} APIs")

# ---------- Routes ----------
@app.post("/api/scan")
def scan(req: ScanRequest, token=Depends(verify_token)):
    discovered = simulate_api_discovery(req.base_url)
    ids = []
    for api in discovered:
        api = update_api_with_ml(api)
        api_registry.insert(api)
        ids.append(api["id"])
    return {"message": f"{len(ids)} APIs discovered", "api_ids": ids}

@app.get("/api/registry")
def registry(
    lifecycle: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "risk_score",
    order: str = "desc",
    token=Depends(verify_token)
):
    Apis = [update_api_with_ml(a) for a in api_registry.all()]
    api_registry.truncate()
    for a in Apis: api_registry.insert(a)
    if lifecycle: Apis = [a for a in Apis if a["lifecycle"] == lifecycle]
    if search: Apis = [a for a in Apis if search.lower() in a["full_url"].lower()]
    Apis.sort(key=lambda x: x.get(sort_by,0), reverse=order=="desc")
    return Apis

@app.get("/api/stats")
def stats(token=Depends(verify_token)):
    Apis = [update_api_with_ml(a) for a in api_registry.all()]
    active = sum(1 for a in Apis if a["lifecycle"]=="active")
    deprecated = sum(1 for a in Apis if a["lifecycle"]=="deprecated")
    orphaned = sum(1 for a in Apis if a["lifecycle"]=="orphaned")
    zombie = sum(1 for a in Apis if a["lifecycle"]=="zombie")
    critical = sum(1 for a in Apis if a.get("risk_score",0)>75)
    posture = max(0, 100 - int(sum(a["risk_score"] for a in Apis)/max(1,len(Apis))))
    return {
        "total": len(Apis), "active": active, "deprecated": deprecated,
        "orphaned": orphaned, "zombie": zombie, "critical_threats": critical,
        "security_posture": posture, "last_updated": datetime.utcnow().isoformat()
    }

@app.get("/api/predict/{api_id}")
def predict(api_id: str, token=Depends(verify_token)):
    api = api_registry.get(TinyQuery().id == api_id)
    if not api: raise HTTPException(404, "API not found")
    api = update_api_with_ml(api)
    forecast = ml.forecast_risk(api)
    api.update(forecast)
    return api

@app.get("/api/attack-path")
def attack_path(token=Depends(verify_token)):
    graph = build_attack_graph()
    graph["note"] = "SIMULATED FOR DEMO PURPOSES"
    return graph

@app.post("/api/defend")
def defend(req: DefendRequest, token=Depends(verify_token)):
    if not req.target_api_ids:
        zombies = [a for a in api_registry.all() if a["lifecycle"]=="zombie" and a["risk_score"]>60]
        target_ids = [a["id"] for a in zombies]
    else:
        target_ids = req.target_api_ids
    defended = []
    for api_id in target_ids:
        api = api_registry.get(TinyQuery().id == api_id)
        if not api: continue
        api["isolated"] = True
        api["risk_score"] = max(0, api["risk_score"]-20)
        api_registry.update(api, TinyQuery().id == api_id)
        honeypot_events.insert({
            "api_id": api_id,
            "timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "persona": random.choice(["APT29","Lazarus","FIN7","Script Kiddie"]),
            "payload": random.choice(["SQLi","Brute force","XML inj","Path traversal"]),
            "simulated": True
        })
        defended.append(api_id)
    return {"message": f"Defense activated on {len(defended)} APIs", "defended_ids": defended}

@app.get("/api/honeypot-events")
def get_honeypot(token=Depends(verify_token)):
    return honeypot_events.all()

@app.get("/api/intel")
def intel(token=Depends(verify_token)):
    return [
        {"source": "OWASP API1:2023", "description": "Broken Object Level Authorization"},
        {"source": "MITRE ATT&CK T1190", "description": "Exploit Public-Facing Application"},
        {"source": "Banking Threat Alert", "description": "Zombie APIs used in recent ransomware attacks"}
    ]

@app.post("/api/ai-assistant")
def ai_assistant(query: AIQuery, token=Depends(verify_token)):
    if OPENAI_API_KEY:
        try:
            import openai
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            resp = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role":"system","content":"Banking cybersecurity expert."},
                          {"role":"user","content":query.message}],
                max_tokens=300
            )
            return {"response": resp.choices[0].message.content, "mode": "openai"}
        except Exception as e:
            return {"response": f"OpenAI error: {e}.", "mode": "offline"}
    else:
        msg = query.message.lower()
        if "zombie" in msg: ans = "A zombie API is an unmanaged, undocumented endpoint. Mitigation: isolate, monitor, enforce auth."
        elif "risk" in msg: ans = "Risk is based on lifecycle, auth, exposure. High-risk APIs should be defended immediately."
        else: ans = "I'm in offline mode. Ask me about zombie APIs, risk scoring, or mitigation."
        return {"response": ans, "mode": "offline"}

@app.get("/health")
def health():
    return {"status": "healthy", "registry_count": len(api_registry)}

# Serve frontend if built
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)