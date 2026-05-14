"""
NECROS X v6.0 — Complete Backend
Every feature from the hackathon proposal implemented.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from tinydb import TinyDB, Query
import random, uuid, time, httpx, os, json

from ml_predictor import predict_zombie, predict_all
from hardware import (
    GPIO_AVAILABLE, led_set, led_blink,
    led_sequence_scan, led_sequence_zombie,
    led_sequence_breach, led_sequence_honeypot,
    led_test, cleanup,
)

app = FastAPI(title="NECROS X", version="6.0.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

db                = TinyDB("necros_registry.json")
registry_table    = db.table("api_registry")
scans_table       = db.table("scans")
attacks_table     = db.table("attacks")
honeypot_table    = db.table("honeypot")
alerts_table      = db.table("alerts")
predictions_table = db.table("predictions")

db_apis:     dict = {}
db_attacks:  list = []
db_honeypot: list = []
db_alerts:   list = []
scan_count:  int  = 0

class ScanRequest(BaseModel):
    target_url: str
    deep_scan: Optional[bool] = False

class AttackRequest(BaseModel):
    api_id: str
    attack_type: Optional[str] = "auto"

class DefendRequest(BaseModel):
    api_id: str
    mode: Optional[str] = "honeypot"

class AIRequest(BaseModel):
    question: str
    api_id: Optional[str] = None

class TerminalRequest(BaseModel):
    command: str

class AutoDefendRequest(BaseModel):
    threshold: Optional[int] = 70

MOCK_APIS = [
    {"path":"/api/v2/auth/login","status":"active",
     "auth":True,"enc":True,"inact":1,"layer":"AUTH",
     "methods":["POST"],"calls":8420,
     "desc":"Primary authentication gateway",
     "owner":"auth-team@corp.io","version":"v2.4.1",
     "created_days_ago":90},
    {"path":"/api/v2/users/profile","status":"active",
     "auth":True,"enc":True,"inact":3,"layer":"DATA",
     "methods":["GET","PUT"],"calls":5100,
     "desc":"User profile management",
     "owner":"platform-team@corp.io","version":"v2.1.0",
     "created_days_ago":120},
    {"path":"/api/v2/payments/charge","status":"active",
     "auth":True,"enc":True,"inact":0,"layer":"FINANCE",
     "methods":["POST"],"calls":2300,
     "desc":"Payment processing endpoint",
     "owner":"payments-team@corp.io","version":"v2.3.0",
     "created_days_ago":60},
    {"path":"/api/v2/dashboard/feed","status":"active",
     "auth":True,"enc":True,"inact":5,"layer":"DATA",
     "methods":["GET"],"calls":12000,
     "desc":"Dashboard data aggregator",
     "owner":"frontend-team@corp.io","version":"v2.0.5",
     "created_days_ago":180},
    {"path":"/api/v2/analytics/track","status":"active",
     "auth":True,"enc":True,"inact":2,"layer":"DATA",
     "methods":["POST"],"calls":9800,
     "desc":"Event tracking pipeline",
     "owner":"data-team@corp.io","version":"v2.2.0",
     "created_days_ago":150},
    {"path":"/api/v2/webhooks/emit","status":"active",
     "auth":True,"enc":True,"inact":7,"layer":"EVENTS",
     "methods":["POST"],"calls":440,
     "desc":"Webhook dispatcher",
     "owner":"platform-team@corp.io","version":"v2.1.0",
     "created_days_ago":200},
    {"path":"/api/v1/legacy-auth","status":"zombie",
     "auth":False,"enc":False,"inact":412,"layer":"AUTH",
     "methods":["GET","POST"],"calls":0,
     "desc":"DECOMMISSIONED — legacy OAuth1 handler",
     "owner":"unknown","version":"v1.0.0",
     "created_days_ago":800},
    {"path":"/api/v0/admin/root","status":"zombie",
     "auth":False,"enc":False,"inact":580,"layer":"ADMIN",
     "methods":["GET","POST","DELETE"],"calls":0,
     "desc":"ABANDONED — original admin panel",
     "owner":"unknown","version":"v0.1.0",
     "created_days_ago":900},
    {"path":"/api/v1/export/csv","status":"deprecated",
     "auth":True,"enc":False,"inact":95,"layer":"DATA",
     "methods":["GET"],"calls":12,
     "desc":"Legacy CSV export — superseded by v2",
     "owner":"data-team@corp.io","version":"v1.2.0",
     "created_days_ago":500},
    {"path":"/api/v0/health/check","status":"deprecated",
     "auth":False,"enc":True,"inact":200,"layer":"OPS",
     "methods":["GET"],"calls":0,
     "desc":"Old health endpoint — use /v2/status",
     "owner":"ops-team@corp.io","version":"v0.2.0",
     "created_days_ago":700},
]

CONNECTIONS = [
    (0,1),(0,2),(1,3),(3,4),(2,5),
    (6,1),(6,7),(7,8),(8,9),(0,3),(1,2)
]

ATTACKS = [
    {"type":"SQL Injection",
     "vector":"' OR 1=1; DROP TABLE users--",
     "sev":"CRITICAL","owasp":"API8","cve":"CVE-2023-44487"},
    {"type":"JWT None-Algorithm",
     "vector":"alg:none — unsigned token accepted",
     "sev":"CRITICAL","owasp":"API2","cve":"CVE-2022-21449"},
    {"type":"SSRF Cloud Metadata",
     "vector":"169.254.169.254/latest/meta-data/iam/",
     "sev":"CRITICAL","owasp":"API7","cve":"CVE-2024-21626"},
    {"type":"BOLA / IDOR",
     "vector":"GET /api/users/1337 — no ownership check",
     "sev":"CRITICAL","owasp":"API1","cve":"CVE-2023-25136"},
    {"type":"Path Traversal",
     "vector":"GET /../../../../etc/shadow",
     "sev":"HIGH","owasp":"API8","cve":"CVE-2023-27898"},
    {"type":"Mass Assignment",
     "vector":"POST {isAdmin:true,role:'superuser'}",
     "sev":"HIGH","owasp":"API6","cve":"CVE-2023-41993"},
    {"type":"Credential Stuffing",
     "vector":"14,823 breached pairs replayed",
     "sev":"HIGH","owasp":"API4","cve":"N/A"},
    {"type":"XXE Injection",
     "vector":"<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
     "sev":"HIGH","owasp":"API8","cve":"CVE-2023-28879"},
]

TRAP_ACTIONS = [
    "Exfiltrating users table via UNION SELECT",
    "Probing internal subnet 10.0.0.0/8",
    "Dumping active session tokens from Redis",
    "Escalating privileges via IDOR on /admin",
    "Injecting Meterpreter reverse shell payload",
    "Lateral movement attempt to database host",
    "Harvesting OAuth2 tokens from response cache",
    "Mapping internal API surface via fuzzer",
]

TRAP_INTEL = [
    "RSA-2048 private key fragment (3 of 5)",
    "12,847 bcrypt password hashes (cost:10)",
    "AWS IAM role: arn:aws:iam::123456789:role/prod",
    "Internal k8s cluster: 10.96.0.1:6443",
    "OAuth2 refresh tokens — no expiry set",
    "Redis AUTH password: r3d1s_pr0d_2024!",
    "PostgreSQL DSN with admin credentials",
]

THREAT_ACTORS = [
    {"name":"APT-29 (Cozy Bear)","origin":"RU",
     "ttps":["T1078","T1190","T1110"]},
    {"name":"Lazarus Group","origin":"KP",
     "ttps":["T1110","T1046"]},
    {"name":"Carbanak","origin":"UN",
     "ttps":["T1059","T1078"]},
    {"name":"FIN7","origin":"UA","ttps":["T1110.004"]},
    {"name":"Anonymous Scanner","origin":"CN",
     "ttps":["T1595","T1046"]},
]

def uid():
    return str(uuid.uuid4())[:8].upper()

def rnd_ip():
    return (f"{random.randint(10,220)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(1,254)}")

def now_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())

def calc_risk(auth,enc,inact,status):
    s=0
    if not auth:  s+=35
    if not enc:   s+=25
    if inact>180: s+=30
    elif inact>60:s+=15
    if status=="zombie":      s+=10
    elif status=="deprecated":s+=5
    return min(s,100)

async def real_scan_url(target_url):
    paths=[
        "/api","/api/v1","/api/v2","/health","/status",
        "/ping","/docs","/openapi.json","/swagger",
        "/graphql","/admin","/auth","/login",
        "/users","/profile","/metrics",
        "/actuator","/actuator/health",
        "/api/health","/v1","/v2","/webhook","/webhooks",
    ]
    if not target_url.startswith("http"):
        target_url="https://"+target_url
    base=target_url.rstrip("/")
    found=[]
    async with httpx.AsyncClient(
        timeout=3.0,follow_redirects=True,verify=False
    ) as client:
        for path in paths:
            try:
                r=await client.get(base+path)
                if r.status_code in (200,201,204,401,403,405,422):
                    found.append({
                        "path":path,
                        "status_code":r.status_code,
                        "has_auth":r.status_code in (401,403),
                        "content_type":r.headers.get("content-type",""),
                    })
            except Exception:
                continue
    return found

def generate_pdf(apis,attacks,honeypot,target):
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
    except ImportError:
        return None
    fname=f"/tmp/necros_{uid()}.pdf"
    c=canvas.Canvas(fname,pagesize=letter)
    w,h=letter
    c.setFillColor(colors.HexColor("#01060e"))
    c.rect(0,h-80,w,80,fill=1,stroke=0)
    c.setFont("Helvetica-Bold",20)
    c.setFillColor(colors.HexColor("#00c8ff"))
    c.drawString(36,h-48,"NECROS X — Security Assessment Report")
    c.setFont("Helvetica",9)
    c.setFillColor(colors.HexColor("#555555"))
    c.drawString(36,h-65,f"Target: {target}   |   {now_ts()}   |   v6.0")
    zombies=[a for a in apis if a.get("status")=="zombie"]
    avg=round(sum(a.get("risk_score",a.get("risk",0))
                  for a in apis)/max(len(apis),1),1)
    tl="CRITICAL" if avg>60 else "HIGH" if avg>40 else "MEDIUM"
    y=h-110
    c.setFont("Helvetica-Bold",14)
    c.setFillColor(colors.HexColor(
        "#ff1a3c" if tl=="CRITICAL" else
        "#ff6600" if tl=="HIGH" else "#ffaa00"))
    c.drawString(36,y,f"THREAT LEVEL: {tl}")
    y-=24
    c.setFont("Helvetica",10)
    c.setFillColor(colors.black)
    for item in [
        f"Total APIs: {len(apis)}",
        f"Zombie APIs: {len(zombies)}",
        f"Deprecated: {sum(1 for a in apis if a.get('status')=='deprecated')}",
        f"Avg Risk: {avg}/100",
        f"Attacks Simulated: {len(attacks)}",
        f"Breaches: {sum(1 for a in attacks if a.get('outcome')=='BREACH')}",
        f"HP Captures: {len(honeypot)}",
    ]:
        c.drawString(36,y,item);y-=18
    y-=16
    c.setFont("Helvetica-Bold",12)
    c.setFillColor(colors.HexColor("#00c8ff"))
    c.drawString(36,y,"API INVENTORY")
    y-=18
    c.setFont("Helvetica-Bold",8)
    c.setFillColor(colors.HexColor("#333"))
    for hdr,xx in [("PATH",36),("STATUS",220),("RISK",290),
                   ("AUTH",336),("TLS",374),("LAYER",412),("OWNER",460)]:
        c.drawString(xx,y,hdr)
    y-=4
    c.line(36,y,w-36,y);y-=12
    c.setFont("Helvetica",7)
    for api in apis:
        if y<80:c.showPage();y=h-60
        risk=api.get("risk_score",api.get("risk",0))
        st=api.get("status","active")
        col=(colors.HexColor("#ff1a3c") if st=="zombie"
             else colors.HexColor("#ff6600")
             if st=="deprecated" else colors.black)
        c.setFillColor(col)
        c.drawString(36,y,api.get("path","")[:25])
        c.drawString(220,y,st.upper())
        c.setFillColor(
            colors.HexColor("#ff1a3c") if risk>=70
            else colors.HexColor("#ff6600") if risk>=45
            else colors.HexColor("#00aa66"))
        c.drawString(290,y,str(risk))
        c.setFillColor(colors.black)
        c.drawString(336,y,"Y" if api.get("auth") else "N")
        c.drawString(374,y,"Y" if api.get("encrypted",
                                          api.get("enc")) else "N")
        c.drawString(412,y,api.get("layer",""))
        c.drawString(460,y,api.get("owner","unknown")[:16])
        y-=12
    if y<180:c.showPage();y=h-60
    y-=20
    c.setFont("Helvetica-Bold",12)
    c.setFillColor(colors.HexColor("#00c8ff"))
    c.drawString(36,y,"AI ZOMBIE PREDICTIONS")
    y-=14
    c.setFont("Helvetica",8)
    c.setFillColor(colors.black)
    for api in apis[:6]:
        if y<80:c.showPage();y=h-60
        pred=predict_zombie(api)
        c.drawString(36,y,
            f"{api.get('path','')[:28]} — "
            f"{pred['zombie_probability']}% ({pred['risk_level']}) "
            f"30d:{pred['prediction_30d']}% "
            f"60d:{pred['prediction_60d']}% "
            f"90d:{pred['prediction_90d']}%")
        y-=13
    if y<180:c.showPage();y=h-60
    y-=20
    c.setFont("Helvetica-Bold",12)
    c.setFillColor(colors.HexColor("#00c8ff"))
    c.drawString(36,y,"RECOMMENDATIONS")
    y-=14
    c.setFont("Helvetica",9)
    c.setFillColor(colors.black)
    for rec in [
        "1. IMMEDIATE: Deploy honeypots on all zombie APIs",
        "2. IMMEDIATE: Rotate credentials for zombie endpoints",
        "3. 24 HRS: Enable auth on unauthenticated APIs",
        "4. 48 HRS: Enforce TLS across all API endpoints",
        "5. 1 WEEK: Implement API lifecycle management policy",
        "6. 1 MONTH: Achieve OWASP API Top 10 compliance",
        "7. ONGOING: Quarterly zombie API discovery audits",
        "8. CI/CD: Add API security gate to deployment pipeline",
    ]:
        c.drawString(36,y,rec);y-=15
    c.setFont("Helvetica",8)
    c.setFillColor(colors.HexColor("#999"))
    c.drawString(36,30,"NECROS X — Autonomous Zombie API Defense System v6.0")
    c.drawString(w-160,30,now_ts())
    c.save()
    return fname

@app.get("/")
def root():
    return {"service":"NECROS X","version":"6.0.0",
            "status":"operational","hardware":GPIO_AVAILABLE,
            "ml_engine":"GradientBoosting v1.0",
            "registry":len(registry_table.all())}

@app.get("/health")
def health():
    return {"status":"ok","hardware":GPIO_AVAILABLE,
            "ts":now_ts(),"ml":"active",
            "registry":len(registry_table.all())}

@app.post("/scan")
async def scan(req:ScanRequest,bg:BackgroundTasks):
    global db_apis,db_attacks,db_honeypot,db_alerts,scan_count
    db_apis={};db_attacks=[];db_honeypot=[];db_alerts=[]
    scan_count+=1
    bg.add_task(led_sequence_scan)
    real_found=[]
    try:
        real_found=await real_scan_url(req.target_url)
    except Exception:
        pass
    conn_map={i:[] for i in range(len(MOCK_APIS))}
    for src_i,dst_i in CONNECTIONS:
        conn_map[src_i].append(dst_i)
    id_by_idx={}
    for i,mock in enumerate(MOCK_APIS):
        aid=uid()
        risk=calc_risk(mock["auth"],mock["enc"],
                       mock["inact"],mock["status"])
        id_by_idx[i]=aid
        ml_pred=predict_zombie({
            "calls_per_day":mock["calls"],
            "inactivity_days":mock["inact"],
            "auth":mock["auth"],"enc":mock["enc"],
            "layer":mock["layer"],"methods":mock["methods"],
        })
        db_apis[aid]={
            "id":aid,"path":mock["path"],
            "name":mock["path"].split("/")[-1].replace("-"," ").title(),
            "desc":mock["desc"],"owner":mock["owner"],
            "version":mock["version"],"status":mock["status"],
            "layer":mock["layer"],"methods":mock["methods"],
            "calls_per_day":mock["calls"],"risk_score":risk,
            "last_seen":("Just now" if mock["inact"]==0
                         else f"{mock['inact']}d ago"),
            "auth":mock["auth"],"encrypted":mock["enc"],
            "inactivity_days":mock["inact"],
            "created_days_ago":mock["created_days_ago"],
            "honeypot":False,"quarantined":False,
            "connections":[],"owasp_flags":(
                ["API1","API2"] if not mock["auth"] else []),
            "discovered_at":now_ts(),
            "real_endpoint":any(ep.get("path","") in mock["path"]
                                for ep in real_found),
            "ml_zombie_probability":ml_pred["zombie_probability"],
            "ml_risk_level":ml_pred["risk_level"],
            "ml_prediction_30d":ml_pred["prediction_30d"],
            "ml_prediction_60d":ml_pred["prediction_60d"],
            "ml_prediction_90d":ml_pred["prediction_90d"],
            "ml_recommendation":ml_pred["recommendation"],
            "ml_predicted_date":ml_pred["predicted_zombie_date"],
            "ml_factors":ml_pred["contributing_factors"],
        }
    for src_i,dst_i in CONNECTIONS:
        src_id=id_by_idx[src_i];dst_id=id_by_idx[dst_i]
        if src_id in db_apis:
            db_apis[src_id]["connections"].append(
                db_apis[dst_id]["path"])
    Q=Query()
    for api in db_apis.values():
        existing=registry_table.search(Q.path==api["path"])
        if existing:
            registry_table.update({
                "last_seen":now_ts(),"risk_score":api["risk_score"],
                "ml_zombie_probability":api["ml_zombie_probability"],
                "scan_count":existing[0].get("scan_count",0)+1,
            },Q.path==api["path"])
        else:
            registry_table.insert({**api,"first_seen":now_ts(),
                                    "scan_count":1})
    total=len(db_apis)
    zombies=[a for a in db_apis.values() if a["status"]=="zombie"]
    depr=sum(1 for a in db_apis.values() if a["status"]=="deprecated")
    avg=int(sum(a["risk_score"] for a in db_apis.values())/total)
    for a in db_apis.values():
        if a["ml_zombie_probability"]>=75 and a["status"]=="active":
            db_alerts.append({
                "id":uid(),"type":"ML_ZOMBIE_PREDICTION","sev":"HIGH",
                "path":a["path"],
                "msg":(f"AI predicts {a['path']}: "
                       f"{a['ml_zombie_probability']}% zombie prob"),
                "ts":now_ts(),"ack":False,
            })
    for z in zombies:
        db_alerts.append({
            "id":uid(),"type":"ZOMBIE_DETECTED","sev":"CRITICAL",
            "path":z["path"],
            "msg":f"Zombie: {z['path']} — {z['inactivity_days']}d inactive",
            "ts":now_ts(),"ack":False,
        })
        bg.add_task(led_sequence_zombie)
    scans_table.insert({
        "scan_id":uid(),"target":req.target_url,"ts":now_ts(),
        "total":total,"zombies":len(zombies),"deprecated":depr,
        "avg_risk":avg,"real_found":len(real_found),
        "scan_number":scan_count,
    })
    tl=("CRITICAL" if avg>60 else "HIGH" if avg>40 else "MEDIUM")
    return {
        "scan_id":uid(),"target":req.target_url,
        "timestamp":now_ts(),"scan_number":scan_count,
        "real_found":len(real_found),
        "summary":{
            "total":total,"active":total-len(zombies)-depr,
            "zombie":len(zombies),"deprecated":depr,
            "avg_risk":avg,"threat_level":tl,
            "ml_high_risk":sum(1 for a in db_apis.values()
                              if a["ml_zombie_probability"]>=50),
        },
        "apis":list(db_apis.values()),"alerts":db_alerts,
    }

@app.get("/apis")
def list_apis():
    return {"count":len(db_apis),"apis":list(db_apis.values())}

@app.get("/apis/{api_id}")
def get_api(api_id:str):
    if api_id not in db_apis:
        raise HTTPException(404,"Not found")
    return db_apis[api_id]

@app.get("/registry")
def get_registry():
    all_apis=registry_table.all()
    return {"count":len(all_apis),"apis":all_apis[-50:],
            "total_ever":len(all_apis)}

@app.get("/registry/stats")
def registry_stats():
    all_apis=registry_table.all()
    return {
        "total_registered":len(all_apis),
        "zombie_ever":sum(1 for a in all_apis
                         if a.get("status")=="zombie"),
        "unique_layers":list(set(a.get("layer","")
                                 for a in all_apis)),
        "avg_risk_all_time":round(
            sum(a.get("risk_score",0) for a in all_apis)
            /max(len(all_apis),1),1),
        "high_ml_risk":sum(1 for a in all_apis
                          if a.get("ml_zombie_probability",0)>=50),
    }

@app.get("/predict/all")
def predict_all_apis():
    if not db_apis:
        return {"predictions":[],"note":"Run scan first"}
    preds=predict_all(list(db_apis.values()))
    for p in preds[:5]:
        predictions_table.insert({**p,"ts":now_ts()})
    return {"predictions":preds,"model":"GradientBoosting",
            "features":8,"timestamp":now_ts()}

@app.get("/predict/{api_id}")
def predict_single(api_id:str):
    if api_id not in db_apis:
        raise HTTPException(404,"Not found")
    api=db_apis[api_id]
    pred=predict_zombie(api)
    return {"api_path":api["path"],"api_id":api_id,
            **pred,"timestamp":now_ts()}

@app.get("/predict/timeline/{api_id}")
def prediction_timeline(api_id:str):
    if api_id not in db_apis:
        raise HTTPException(404,"Not found")
    api=db_apis[api_id];pred=predict_zombie(api)
    return {
        "api_path":api["path"],
        "current":pred["zombie_probability"],
        "timeline":[
            {"days":0,"probability":pred["zombie_probability"]},
            {"days":30,"probability":pred["prediction_30d"]},
            {"days":60,"probability":pred["prediction_60d"]},
            {"days":90,"probability":pred["prediction_90d"]},
        ],
        "recommendation":pred["recommendation"],
        "factors":pred["contributing_factors"],
    }

@app.post("/simulate")
async def simulate(req:AttackRequest,bg:BackgroundTasks):
    if req.api_id not in db_apis:
        raise HTTPException(404,"Not found")
    api=db_apis[req.api_id]
    attack=random.choice(ATTACKS)
    actor=random.choice(THREAT_ACTORS)
    if api["honeypot"]:
        outcome="TRAPPED";detail="Attacker diverted. Fingerprint captured."
    elif api.get("quarantined"):
        outcome="BLOCKED";detail="API quarantined. All requests blocked."
    elif not api["auth"]:
        outcome="BREACH";detail="No auth. Full unauthorized access."
        bg.add_task(led_sequence_breach)
    elif api["status"] in ("zombie","deprecated") and not api["encrypted"]:
        outcome="BREACH";detail="Deprecated token exploited. Data exposed."
        bg.add_task(led_sequence_breach)
    else:
        outcome="BLOCKED";detail="WAF + rate-limit triggered."
    log={
        "log_id":uid(),"timestamp":now_ts(),"attacker_ip":rnd_ip(),
        "threat_actor":actor["name"],"origin":actor["origin"],
        "ttps":actor["ttps"],"target_api":api["path"],
        "attack_type":attack["type"],"vector":attack["vector"],
        "severity":attack["sev"],"owasp":attack["owasp"],
        "cve":attack["cve"],"outcome":outcome,"detail":detail,
    }
    db_attacks.append(log);attacks_table.insert(log)
    if outcome=="BREACH":
        db_alerts.append({
            "id":uid(),"type":"BREACH_DETECTED","sev":"CRITICAL",
            "path":api["path"],
            "msg":f"BREACH: {api['path']} via {attack['type']}",
            "ts":now_ts(),"ack":False,
        })
    return log

@app.post("/defend")
async def defend(req:DefendRequest,bg:BackgroundTasks):
    if req.api_id not in db_apis:
        raise HTTPException(404,"Not found")
    api=db_apis[req.api_id]
    if api["status"]=="active" and not api.get("quarantined"):
        raise HTTPException(400,"Cannot convert active API")
    if api["honeypot"]:
        raise HTTPException(400,"Already a honeypot")
    if req.mode=="quarantine":
        db_apis[req.api_id].update({
            "quarantined":True,"status":"quarantined",
            "risk_score":max(api["risk_score"]-20,5),
        })
        db_alerts.append({
            "id":uid(),"type":"API_QUARANTINED","sev":"INFO",
            "path":api["path"],
            "msg":f"API quarantined: {api['path']}",
            "ts":now_ts(),"ack":False,
        })
        return {"status":"QUARANTINED","api_path":api["path"],
                "message":f"'{api['path']}' quarantined."}
    db_apis[req.api_id].update({
        "honeypot":True,"status":"honeypot",
        "risk_score":max(api["risk_score"]-40,5),
        "hp_activated":now_ts(),
    })
    traps=[]
    for _ in range(random.randint(2,5)):
        entry={
            "attacker_ip":rnd_ip(),
            "threat_actor":random.choice(THREAT_ACTORS)["name"],
            "action":random.choice(TRAP_ACTIONS),
            "status":"Trapped in honeypot",
            "intel_captured":random.choice(TRAP_INTEL),
            "dwell_min":random.randint(4,62),
            "timestamp":now_ts(),
        }
        traps.append(entry);db_honeypot.append(entry)
        honeypot_table.insert(entry)
    bg.add_task(led_sequence_honeypot)
    db_alerts.append({
        "id":uid(),"type":"HONEYPOT_ACTIVE","sev":"INFO",
        "path":api["path"],
        "msg":f"Honeypot live: {api['path']} — {len(traps)} trapped",
        "ts":now_ts(),"ack":False,
    })
    return {
        "status":"HONEYPOT_ACTIVATED","api_path":api["path"],
        "message":f"'{api['path']}' is now a honeypot.",
        "trap_logs":traps,"intel_value":"HIGH",
        "dwell_estimate":"40–60 min",
    }
@app.post("/defend/auto")
async def auto_defend(req:AutoDefendRequest,bg:BackgroundTasks):
    threshold=req.threshold or 70
    acted=[]
    for api_id,api in db_apis.items():
        if (api["status"] in ("zombie","deprecated")
                and api["risk_score"]>=threshold
                and not api["honeypot"]):
            db_apis[api_id].update({
                "honeypot":True,"status":"honeypot",
                "risk_score":max(api["risk_score"]-40,5),
            })
            for _ in range(random.randint(1,3)):
                entry={
                    "attacker_ip":rnd_ip(),
                    "action":random.choice(TRAP_ACTIONS),
                    "status":"Auto-trapped",
                    "intel_captured":random.choice(TRAP_INTEL),
                    "dwell_min":random.randint(4,30),
                    "timestamp":now_ts(),
                }
                db_honeypot.append(entry);honeypot_table.insert(entry)
            acted.append({"api_path":api["path"],
                          "old_risk":api["risk_score"]})
            bg.add_task(led_sequence_honeypot)
    return {
        "status":"AUTO_DEFEND_COMPLETE","acted_on":len(acted),
        "apis":acted,
        "message":(f"Auto-defense: {len(acted)} honeypots deployed."
                  if acted else "No APIs met criteria."),
        "timestamp":now_ts(),
    }

@app.get("/graph")
def graph():
    nodes,edges=[],[]
    path_to_id={a["path"]:a["id"] for a in db_apis.values()}
    for api in db_apis.values():
        nodes.append({
            "id":api["id"],"path":api["path"],
            "layer":api["layer"],"status":api["status"],
            "risk":api["risk_score"],"honeypot":api["honeypot"],
            "calls":api["calls_per_day"],"auth":api["auth"],
            "enc":api["encrypted"],
            "ml_prob":api.get("ml_zombie_probability",0),
            "owner":api.get("owner","unknown"),
            "desc":api.get("desc",""),
        })
        for conn in api["connections"]:
            tid=path_to_id.get(conn)
            if tid:
                edges.append({"source":api["id"],"target":tid,
                               "zombie":api["status"]=="zombie"})
    return {"nodes":nodes,"edges":edges}

@app.get("/attack/paths")
def attack_paths():
    zombies=[a for a in db_apis.values()
             if a["status"]=="zombie"]
    paths=[]
    for z in zombies:
        chain=[z["path"]]
        for conn in z.get("connections",[]):
            chain.append(conn)
            for api in db_apis.values():
                if api["path"]==conn:
                    for hop2 in api.get("connections",[])[:2]:
                        if hop2 not in chain:
                            chain.append(hop2)
        paths.append({
            "entry_point":z["path"],"risk":z["risk_score"],
            "attack_chain":chain,"depth":len(chain),
            "financial_reach":any(
                "payment" in p or "finance" in p for p in chain),
        })
    return {
        "attack_paths":paths,
        "financial_exposed":any(p["financial_reach"] for p in paths),
    }

@app.get("/logs/attacks")
def attack_logs():
    return {"count":len(db_attacks),"logs":db_attacks}

@app.get("/logs/honeypot")
def honeypot_logs():
    return {"count":len(db_honeypot),"logs":db_honeypot}

@app.get("/alerts")
def get_alerts():
    return {"count":len(db_alerts),"alerts":db_alerts}

@app.get("/scans/history")
def scan_history():
    all_scans=scans_table.all()
    return {"count":len(all_scans),"scans":all_scans[-10:]}

@app.get("/stats")
def stats():
    apis=list(db_apis.values())
    if not apis:return{"total_apis":0}
    breach =sum(1 for l in db_attacks if l["outcome"]=="BREACH")
    blocked=sum(1 for l in db_attacks if l["outcome"]=="BLOCKED")
    trapped=sum(1 for l in db_attacks if l["outcome"]=="TRAPPED")
    return {
        "total_apis":len(apis),
        "zombie_count":sum(1 for a in apis if a["status"]=="zombie"),
        "honeypot_count":sum(1 for a in apis if a["honeypot"]),
        "deprecated_count":sum(1 for a in apis
                               if a["status"]=="deprecated"),
        "ml_high_risk":sum(1 for a in apis
                          if a.get("ml_zombie_probability",0)>=50),
        "attack_events":len(db_attacks),
        "intel_captures":len(db_honeypot),
        "avg_risk":round(sum(a["risk_score"] for a in apis)
                        /len(apis),1),
        "breach_count":breach,"blocked_count":blocked,
        "trapped_count":trapped,
        "breach_rate":round(breach/max(len(db_attacks),1)*100,1),
        "open_alerts":sum(1 for a in db_alerts if not a["ack"]),
        "scan_count":scan_count,"hardware_active":GPIO_AVAILABLE,
        "registry_total":len(registry_table.all()),
        "total_scans":len(scans_table.all()),
    }

@app.get("/threats")
def threats():
    return {
        "feed":[
            {"id":uid(),"actor":"APT-29","sev":"CRITICAL",
             "ts":now_ts(),
             "title":"Active campaign on legacy auth endpoints",
             "iocs":["185.220.101.0/24","jwt-bypass-kit-v3"],
             "ttps":["T1078","T1190","T1110"]},
            {"id":uid(),"actor":"Mass Scanner","sev":"HIGH",
             "ts":now_ts(),
             "title":"ZGrab2 sweep — 847 API targets globally",
             "iocs":["194.165.16.0/24","ZGrab/2.x"],
             "ttps":["T1595","T1046"]},
            {"id":uid(),"actor":"Lazarus Group","sev":"HIGH",
             "ts":now_ts(),
             "title":"SSRF kit targeting cloud metadata",
             "iocs":["169.254.169.254"],
             "ttps":["T1090","T1190"]},
            {"id":uid(),"actor":"FIN7","sev":"MEDIUM",
             "ts":now_ts(),
             "title":"47M credential combo on finance APIs",
             "iocs":["combo-2024-Q4.txt"],
             "ttps":["T1110.004"]},
        ],
        "stats":{
            "active_campaigns":4,"iocs_tracked":1247,
            "nations_involved":6,"last_updated":now_ts(),
        }
    }

@app.get("/report/pdf")
def pdf_report():
    if not db_apis:
        raise HTTPException(400,"Run a scan first")
    try:
        fname=generate_pdf(list(db_apis.values()),
                           db_attacks,db_honeypot,
                           "Last Scanned Target")
        if not fname:raise HTTPException(500,"PDF failed")
        return FileResponse(fname,media_type="application/pdf",
                            filename="necros-x-report.pdf")
    except Exception as e:
        raise HTTPException(500,str(e))

@app.post("/hardware/test")
async def hw_test():
    if not GPIO_AVAILABLE:
        return {"status":"no_hardware",
                "msg":"Software mode — no GPIO detected"}
    await led_test()
    return {"status":"ok","msg":"LED test complete","hardware":True}

@app.post("/hardware/alert")
async def hw_alert(color:str="red",times:int=3):
    await led_blink(color,times=times)
    return {"status":"ok","color":color,"times":times}

@app.post("/ai/analyze")
async def ai_analyze(req:AIRequest):
    api_key=os.environ.get("ANTHROPIC_API_KEY","")
    ctx_apis=list(db_apis.values())
    zombies=[a for a in ctx_apis if a["status"]=="zombie"]
    selected=(db_apis.get(req.api_id) if req.api_id else None)
    ml_high=[a for a in ctx_apis
             if a.get("ml_zombie_probability",0)>=50
             and a["status"]=="active"]
    context=f"""
NECROS X v6.0:
APIs:{len(ctx_apis)} Zombies:{len(zombies)}
ML at-risk:{len(ml_high)} Attacks:{len(db_attacks)}
Breaches:{sum(1 for a in db_attacks if a.get('outcome')=='BREACH')}
HP captures:{len(db_honeypot)} Hardware:{GPIO_AVAILABLE}
APIs:
{json.dumps([{
    'path':a['path'],'status':a['status'],
    'risk':a['risk_score'],'auth':a['auth'],
    'enc':a['encrypted'],'days':a['inactivity_days'],
    'calls':a['calls_per_day'],
    'ml_prob':a.get('ml_zombie_probability',0),
    'ml_30d':a.get('ml_prediction_30d',0),
    'ml_90d':a.get('ml_prediction_90d',0),
} for a in ctx_apis],indent=2)}
{f'Selected:{json.dumps(selected,indent=2)}' if selected else ''}
"""
if api_key:
        try:
            async with httpx.AsyncClient(timeout=30) as cl:
                r=await cl.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key":api_key,
                        "anthropic-version":"2023-06-01",
                        "content-type":"application/json",
                    },
                    json={
                        "model":"claude-sonnet-4-5",
                        "max_tokens":1024,
                        "system":("You are NECROS — elite API security analyst. "
                                  "Expert in zombie APIs, ML prediction, OWASP, "
                                  "honeypot defense. Be precise and actionable."),
                        "messages":[{"role":"user",
                                     "content":f"{context}\nQuestion:{req.question}"}],
                    }
                )
                if r.status_code==200:
                    d=r.json()
                    return {"answer":d["content"][0]["text"],
                            "model":"claude-sonnet-4-5",
                            "powered_by":"Anthropic Claude"}
        except Exception:
            pass
    q=req.question.lower()
    zc=len(zombies)
    avg=round(sum(a["risk_score"] for a in ctx_apis)
              /max(len(ctx_apis),1),1) if ctx_apis else 0
    if any(w in q for w in ["predict","future","ml","forecast","become","90","30"]):
        ans=("## AI Zombie Prediction Engine\n\n"
             "**Model:** GradientBoosting (8 features)\n\n"
             "**Features:** calls_per_day, inactivity_days, auth, enc, "
             "layer_risk, method_count, estimated_age, usage_drop_rate\n\n"
             "**Current predictions:**\n")
        for a in sorted(ctx_apis,
            key=lambda x:x.get("ml_zombie_probability",0),
            reverse=True)[:5]:
            ans+=(f"• `{a['path']}` — "
                  f"**{a.get('ml_zombie_probability',0)}%** | "
                  f"30d:{a.get('ml_prediction_30d',0)}% | "
                  f"90d:{a.get('ml_prediction_90d',0)}%\n")
        ans+="\n**Key value:** 90-day early warning before APIs become threats."
    elif any(w in q for w in ["zombie","legacy","inactive"]):
        ans=f"## Zombie API Analysis — URGENCY: CRITICAL\n\n**{zc} zombies:**\n"
        for z in zombies:
            ans+=(f"• `{z['path']}` — Risk:{z['risk_score']}/100 "
                  f"| {z['inactivity_days']}d inactive "
                  f"| ML:{z.get('ml_zombie_probability',0)}%\n")
        ans+=("\n**Fix:** 1. Honeypot → 2. Rotate creds → "
              "3. Firewall disable\n**OWASP:** API9:2023")
    elif any(w in q for w in ["honeypot","trap","defend"]):
        ans=("## Honeypot Defense\n\n"
             "**Rule:** Deploy honeypot BEFORE disabling zombie.\n\n"
             "**Captures:** Attacker IPs, tools, credentials, payloads\n"
             "**Auto-defend:** Deploys all honeypots simultaneously.\n"
             "**Average dwell:** 47 minutes of free threat intel.")
    elif any(w in q for w in ["fix","first","priority"]):
        ans=(f"## Priority Plan\n\nAvg Risk: {avg}/100\n\n"
             f"TODAY: Honeypots on {zc} zombie APIs\n"
             "48 HRS: Enable auth on all endpoints (+35 pts each)\n"
             "1 WEEK: Enforce TLS across all APIs (+25 pts each)")
    else:
        ans=(f"## Summary\n\nThreat: {'CRITICAL' if avg>60 else 'HIGH' if avg>40 else 'MEDIUM'}\n"
             f"• {len(ctx_apis)} APIs | {zc} zombies | {len(ml_high)} ML at-risk\n"
             f"• Avg risk: {avg}/100\n\n"
             "Ask about: ML predictions, zombies, attack paths, honeypots.")
    return {"answer":ans,"model":"NECROS-AI v6.0",
            "powered_by":"GradientBoosting ML",
            "note":"Set ANTHROPIC_API_KEY for Claude AI"}

@app.post("/terminal")
def terminal(req:TerminalRequest):
    cmd=req.command.strip().lower()
    parts=cmd.split()
    if not parts:return{"output":""}
    base=parts[0];args=parts[1:]
    if base=="help":
        return{"output":"""NECROS X Terminal v6.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  scan <url>      Scan API surface
  apis            List all APIs (with ML%)
  zombies         Show zombie APIs
  predict         ML predictions all
  predict <id>    ML prediction single
  attack <id>     Simulate attack
  honeypot <id>   Deploy honeypot
  autodefend      Auto-honeypot all zombies
  paths           Attack path visualization
  stats           System statistics
  alerts          Active alerts
  threats         Threat intel feed
  risk <id>       Risk breakdown
  history         Scan history
  hw test         Test LED hardware
  clear           Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""}
    elif base in("apis","ls"):
        if not db_apis:return{"output":"No APIs. Run: scan <url>"}
        lines=["ID       PATH                    STATUS      RISK  ML%","─"*58]
        for a in db_apis.values():
            lines.append(f"{a['id']:<9}{a['path'][:22]:<23}"
                        f"{a['status']:<12}{a['risk_score']:<6}"
                        f"{a.get('ml_zombie_probability',0):.0f}%")
        return{"output":"\n".join(lines)}
    elif base=="zombies":
        zs=[a for a in db_apis.values() if a["status"]=="zombie"]
        if not zs:return{"output":"No zombies detected."}
        lines=["☠ ZOMBIE APIs:","─"*54]
        for z in zs:
            lines.append(f"  {z['id']} | {z['path']}")
            lines.append(f"  Risk:{z['risk_score']}/100"
                        f" | Inactive:{z['inactivity_days']}d"
                        f" | ML:{z.get('ml_zombie_probability',0):.0f}%")
        return{"output":"\n".join(lines)}
    elif base=="predict":
        if args:
            aid=args[0].upper()
            api=db_apis.get(aid)
            if not api:return{"output":f"API {aid} not found."}
            p=predict_zombie(api)
            return{"output":(
                f"ML PREDICTION: {api['path']}\n{'─'*50}\n"
                f"Zombie Probability: {p['zombie_probability']}%\n"
                f"Risk Level:         {p['risk_level']}\n"
                f"Confidence:         {p['confidence']}%\n"
                f"30-day forecast:    {p['prediction_30d']}%\n"
                f"60-day forecast:    {p['prediction_60d']}%\n"
                f"90-day forecast:    {p['prediction_90d']}%\n"
                f"Est. zombie date:   {p['predicted_zombie_date']}\n"
                f"{'─'*50}\n{p['recommendation']}"
            )}
        else:
            preds=predict_all(list(db_apis.values()))
            lines=["ML PREDICTIONS:","─"*62,
                   f"{'PATH':<28}{'PROB':>6}{'30D':>6}{'60D':>6}{'90D':>6}  LEVEL",
                   "─"*62]
            for p in preds[:8]:
                lines.append(
                    f"{p['path'][:27]:<28}"
                    f"{p['zombie_probability']:>5}%"
                    f"{p['prediction_30d']:>5}%"
                    f"{p['prediction_60d']:>5}%"
                    f"{p['prediction_90d']:>5}%"
                    f"  {p['risk_level']}")
            return{"output":"\n".join(lines)}
    elif base=="stats":
        s=stats()
        hw="ACTIVE ✓" if GPIO_AVAILABLE else "Software mode"
        return{"output":(
            f"NECROS X v6.0\n{'─'*32}\n"
            f"Total APIs:    {s.get('total_apis',0)}\n"
            f"Zombie APIs:   {s.get('zombie_count',0)}\n"
            f"ML At-Risk:    {s.get('ml_high_risk',0)}\n"
            f"Honeypots:     {s.get('honeypot_count',0)}\n"
            f"Avg Risk:      {s.get('avg_risk',0)}/100\n"
            f"Attacks:       {s.get('attack_events',0)}\n"
            f"Breaches:      {s.get('breach_count',0)}\n"
            f"HP Captures:   {s.get('intel_captures',0)}\n"
            f"Hardware:      {hw}"
        )}
    elif base=="autodefend":
        acted=[]
        for api_id,api in db_apis.items():
            if api["status"] in("zombie","deprecated") and not api["honeypot"]:
                db_apis[api_id].update({
                    "honeypot":True,"status":"honeypot",
                    "risk_score":max(api["risk_score"]-40,5)})
                acted.append(api["path"])
        return{"output":(
            f"AUTO-DEFEND COMPLETE\n{'─'*44}\n"
            f"Deployed: {len(acted)} honeypots\n"
            +"\n".join(f"  ✓ {p}" for p in acted)
            +(f"\nAll zombie APIs now trapping attackers."
              if acted else "\nNo targets found.")
        ),"action":"autodefend"}
    elif base=="paths":
        zs=[a for a in db_apis.values() if a["status"]=="zombie"]
        if not zs:return{"output":"No zombie entry points."}
        lines=["ATTACK PATHS:","─"*50]
        for z in zs:
            chain=[z["path"]]+z.get("connections",[])[:3]
            lines.append(" → ".join(p.split("/")[-1] for p in chain))
            lines.append(f"  Entry:{z['path']} | Depth:{len(chain)}")
        return{"output":"\n".join(lines)}
    elif base=="alerts":
        open_a=[a for a in db_alerts if not a["ack"]]
        if not open_a:return{"output":"No active alerts."}
        lines=[f"🔔 {len(open_a)} ALERTS:","─"*50]
        for a in open_a:lines.append(f"  [{a['sev']}] {a['msg']}")
        return{"output":"\n".join(lines)}
    elif base=="history":
        scans=scans_table.all()[-5:]
        if not scans:return{"output":"No scan history yet."}
        lines=["RECENT SCANS:","─"*58]
        for s in reversed(scans):
            lines.append(f"  {s.get('ts','')[:16]} | "
                        f"{s.get('target','')[:24]} | "
                        f"Zombies:{s.get('zombies',0)}")
        return{"output":"\n".join(lines)}
    elif base=="scan":
        t=args[0] if args else "https://api.target.com"
        return{"output":f"Scanning {t}...\nSee GUI for animation.",
               "action":"scan","target":t}
    elif base=="threats":
        return{"output":(
            "🌐 THREAT INTELLIGENCE\n"+"─"*44+"\n"
            "[CRITICAL] APT-29 — Legacy auth campaign\n"
            "[HIGH]     Mass Scanner — ZGrab2 sweep\n"
            "[HIGH]     Lazarus — SSRF cloud metadata\n"
            "[MEDIUM]   FIN7 — 47M credential combo\n"
            "─"*44+"\nActive: 4 | IOCs: 1,247"
        )}
    elif base=="risk" and args:
        aid=args[0].upper()
        api=db_apis.get(aid)
        if not api:return{"output":f"API {aid} not found."}
        lines=[f"RISK: {api['path']}","─"*50,
               f"Score: {api['risk_score']}/100",
               f"ML:    {api.get('ml_zombie_probability',0):.1f}%",
               f"Owner: {api.get('owner','unknown')}","FACTORS:"]
        if not api["auth"]:lines.append("  ✗ No Auth   +35 [API2]")
        if not api["encrypted"]:lines.append("  ✗ No TLS    +25 [API8]")
        if api["inactivity_days"]>180:
            lines.append(f"  ✗ {api['inactivity_days']}d inactive +30 [API9]")
        return{"output":"\n".join(lines)}
    elif base=="attack" and args:
        aid=args[0].upper()
        if aid not in db_apis:return{"output":f"API {aid} not found."}
        api=db_apis[aid];atk=random.choice(ATTACKS)
        out=("TRAPPED" if api["honeypot"] else
             "BREACH" if not api["auth"] else "BLOCKED")
        return{"output":(
            f"⚡ ATTACK SIM\n{'─'*44}\n"
            f"Target: {api['path']}\nAttack: {atk['type']}\n"
            f"OWASP:  {atk['owasp']}\nCVE:    {atk['cve']}\n"
            f"{'─'*44}\nOUTCOME: ■ {out}"
        ),"outcome":out}
    elif base in("honeypot","hp") and args:
        aid=args[0].upper()
        if aid not in db_apis:return{"output":f"API {aid} not found."}
        api=db_apis[aid]
        if api["status"]=="active":return{"output":"Cannot convert active API."}
        db_apis[aid].update({"honeypot":True,"status":"honeypot",
            "risk_score":max(api["risk_score"]-40,5)})
        return{"output":(
            f"🍯 HONEYPOT LIVE\n{'─'*44}\n"
            f"Target:   {api['path']}\n"
            f"Captured: {random.randint(1,4)} attackers\n"
            f"Intel:    {random.choice(TRAP_INTEL)}"
        ),"action":"honeypot"}
    elif base=="hw" and args and args[0]=="test":
        return{"output":("LED test triggered." if GPIO_AVAILABLE
               else "No hardware connected."),"action":"hw_test"}
    elif base=="clear":
        return{"output":"","clear":True}
    else:
        return{"output":f"Unknown: '{cmd}'\nType 'help'."}

@app.on_event("shutdown")
def shutdown():
    cleanup()