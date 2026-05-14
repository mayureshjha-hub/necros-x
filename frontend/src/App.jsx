import {
  useState,useEffect,useRef,useCallback,
} from "react";

const uid=()=>Math.random().toString(36).slice(2,9).toUpperCase();
const rnd=(a,b)=>Math.floor(Math.random()*(b-a+1))+a;
const rndIP=()=>`${rnd(10,220)}.${rnd(0,255)}.${rnd(0,255)}.${rnd(1,254)}`;
const ts=()=>new Date().toISOString().slice(0,19).replace("T"," ")+" UTC";
const clamp=(v,lo,hi)=>Math.max(lo,Math.min(hi,v));
const API="";

const C={
  bg:"#01060e",bg2:"#020c1a",bg3:"#040f20",
  panel:"#061525",border:"#0b2040",edge:"#103060",
  neon:"#00c8ff",neon2:"#0078b8",neon3:"#00fff0",
  green:"#00ffaa",red:"#ff1a3c",orange:"#ff6600",
  amber:"#ffaa00",plasma:"#8800ff",gold:"#ffd700",
  text:"#a8cce8",muted:"#3a587a",dim:"#1a3050",
};
const sColor=s=>
  s==="zombie"?"#ff1a3c":s==="deprecated"?"#ff6600":
  s==="honeypot"?"#00c8ff":s==="quarantined"?"#ffaa00":"#00ffaa";

const MOCK_APIS_RAW=[
  {path:"/api/v2/auth/login",st:"active",auth:1,enc:1,days:1,layer:"AUTH",cpd:8420,
   desc:"Primary authentication gateway",owner:"auth-team@corp.io",
   version:"v2.4.1",methods:["POST"],created:90},
  {path:"/api/v2/users/profile",st:"active",auth:1,enc:1,days:3,layer:"DATA",cpd:5100,
   desc:"User profile management",owner:"platform-team@corp.io",
   version:"v2.1.0",methods:["GET","PUT"],created:120},
  {path:"/api/v2/payments/charge",st:"active",auth:1,enc:1,days:0,layer:"FINANCE",cpd:2300,
   desc:"Payment processing endpoint",owner:"payments-team@corp.io",
   version:"v2.3.0",methods:["POST"],created:60},
  {path:"/api/v2/dashboard/feed",st:"active",auth:1,enc:1,days:5,layer:"DATA",cpd:12000,
   desc:"Dashboard data aggregator",owner:"frontend-team@corp.io",
   version:"v2.0.5",methods:["GET"],created:180},
  {path:"/api/v2/analytics/track",st:"active",auth:1,enc:1,days:2,layer:"DATA",cpd:9800,
   desc:"Event tracking pipeline",owner:"data-team@corp.io",
   version:"v2.2.0",methods:["POST"],created:150},
  {path:"/api/v2/webhooks/emit",st:"active",auth:1,enc:1,days:7,layer:"EVENTS",cpd:440,
   desc:"Webhook dispatcher",owner:"platform-team@corp.io",
   version:"v2.1.0",methods:["POST"],created:200},
  {path:"/api/v1/legacy-auth",st:"zombie",auth:0,enc:0,days:412,layer:"AUTH",cpd:0,
   desc:"DECOMMISSIONED — legacy OAuth1 handler",owner:"unknown",
   version:"v1.0.0",methods:["GET","POST"],created:800},
  {path:"/api/v0/admin/root",st:"zombie",auth:0,enc:0,days:580,layer:"ADMIN",cpd:0,
   desc:"ABANDONED — original admin panel",owner:"unknown",
   version:"v0.1.0",methods:["GET","POST","DELETE"],created:900},
  {path:"/api/v1/export/csv",st:"deprecated",auth:1,enc:0,days:95,layer:"DATA",cpd:12,
   desc:"Legacy CSV export — superseded by v2",owner:"data-team@corp.io",
   version:"v1.2.0",methods:["GET"],created:500},
  {path:"/api/v0/health/check",st:"deprecated",auth:0,enc:1,days:200,layer:"OPS",cpd:0,
   desc:"Old health endpoint — use /v2/status",owner:"ops-team@corp.io",
   version:"v0.2.0",methods:["GET"],created:700},
];
const MOCK_EDGES=[[0,1],[0,2],[1,3],[3,4],[2,5],[6,1],[6,7],[7,8],[8,9],[0,3],[1,2]];
const MOCK_ATKS=[
  {type:"SQL Injection",vec:"' OR 1=1; DROP TABLE users--",sev:"CRITICAL",owasp:"API8",cve:"CVE-2023-44487"},
  {type:"JWT None-Algorithm",vec:"alg:none — unsigned token accepted",sev:"CRITICAL",owasp:"API2",cve:"CVE-2022-21449"},
  {type:"SSRF Cloud Metadata",vec:"169.254.169.254/latest/meta-data/iam/",sev:"CRITICAL",owasp:"API7",cve:"CVE-2024-21626"},
  {type:"BOLA/IDOR",vec:"GET /api/users/1337 — no ownership check",sev:"CRITICAL",owasp:"API1",cve:"CVE-2023-25136"},
  {type:"Path Traversal",vec:"GET /../../../../etc/shadow",sev:"HIGH",owasp:"API8",cve:"CVE-2023-27898"},
  {type:"Mass Assignment",vec:"POST {isAdmin:true,role:'superuser'}",sev:"HIGH",owasp:"API6",cve:"CVE-2023-41993"},
  {type:"Credential Stuffing",vec:"14,823 breached pairs replayed",sev:"HIGH",owasp:"API4",cve:"N/A"},
];
const MOCK_ACTIONS=[
  "Exfiltrating users table via UNION SELECT",
  "Probing internal subnet 10.0.0.0/8",
  "Dumping session tokens from Redis",
  "Escalating privileges via IDOR",
  "Injecting Meterpreter reverse shell",
  "Lateral movement to database host",
];
const MOCK_INTEL=[
  "RSA-2048 private key fragment (3 of 5)",
  "12,847 bcrypt password hashes (cost:10)",
  "AWS IAM role credentials",
  "Internal k8s cluster: 10.96.0.1:6443",
  "OAuth2 refresh tokens — no expiry",
  "PostgreSQL DSN with admin credentials",
];
const THREAT_FEED=[
  "APT-29 active — legacy auth endpoints CRITICAL",
  "Mass scan wave — 847 zombie APIs targeted globally",
  "JWT none-alg PoC published — patch NOW",
  "47M credential combo against finance APIs",
  "SSRF targeting AWS cloud metadata service",
  "Carbanak targeting admin endpoints — no auth",
  "New BOLA exploit kit — REST APIs primary target",
  "FIN7 mass assignment attacks on deprecated endpoints",
];

function mlPredict(api){
  const calls=api.calls_per_day||api.cpd||0;
  const inact=api.days||api.inactivity_days||0;
  const auth=api.auth?1:0;
  const enc=api.enc||api.encrypted?1:0;
  let prob=0;
  if(calls===0)prob+=0.40;
  else if(calls<10)prob+=0.20;
  else if(calls<100)prob+=0.05;
  if(inact>180)prob+=0.30;
  else if(inact>60)prob+=0.15;
  else if(inact>30)prob+=0.05;
  if(!auth)prob+=0.20;
  if(!enc)prob+=0.10;
  const lRisk={AUTH:0.15,ADMIN:0.20,DATA:0.05,FINANCE:0.05,EVENTS:0.05,OPS:0.10};
  prob+=lRisk[api.layer]||0.05;
  prob=Math.min(prob,1.0);
  return{
    zombie_probability:Math.round(prob*100*10)/10,
    risk_level:prob>=0.75?"CRITICAL":prob>=0.50?"HIGH":prob>=0.25?"MEDIUM":"LOW",
    prediction_30d:Math.round(Math.min(prob*1.10,1)*100*10)/10,
    prediction_60d:Math.round(Math.min(prob*1.22,1)*100*10)/10,
    prediction_90d:Math.round(Math.min(prob*1.38,1)*100*10)/10,
    confidence:Math.round((0.65+Math.random()*0.2)*100),
    recommendation:prob>=0.75?"IMMEDIATE: Deploy honeypot and rotate credentials.":
      prob>=0.50?"HIGH PRIORITY: Security review within 48h.":
      prob>=0.25?"MONITOR: Add to watchlist.":"HEALTHY: Standard monitoring.",
    predicted_zombie_date:prob>=0.75?"Already at risk":
      prob>=0.50?"~30 days":prob>=0.25?"~90 days":">12 months",
    factors:[
      calls===0&&{f:"Zero daily calls",impact:"CRITICAL",pts:40},
      inact>180&&{f:`${inact}d inactive`,impact:"CRITICAL",pts:30},
      !auth&&{f:"No authentication",impact:"HIGH",pts:20},
      !enc&&{f:"No TLS",impact:"MEDIUM",pts:10},
    ].filter(Boolean),
  };
}

function calcRisk(a){
  let s=0;
  if(!a.auth)s+=35;if(!a.enc)s+=25;
  if(a.days>180)s+=30;else if(a.days>60)s+=15;
  if(a.st==="zombie")s+=10;else if(a.st==="deprecated")s+=5;
  return Math.min(s,100);
}

function mkApis(){
const arr=MOCK_APIS_RAW.map((r,i)=>{
    const ml=mlPredict(r);
    return{
      id:uid(),idx:i,path:r.path,layer:r.layer,
      name:r.path.split("/").pop().replace(/-/g," "),
      desc:r.desc,owner:r.owner,version:r.version,
      status:r.st,risk:calcRisk(r),
      auth:!!r.auth,enc:!!r.enc,
      days:r.days,seen:r.days===0?"Just now":`${r.days}d ago`,
      honeypot:false,quarantined:false,conns:[],
      calls_per_day:r.cpd,methods:r.methods,
      created_days_ago:r.created,
      owasp_flags:!r.auth?["API1","API2"]:[],
      ml_zombie_probability:ml.zombie_probability,
      ml_risk_level:ml.risk_level,
      ml_prediction_30d:ml.prediction_30d,
      ml_prediction_60d:ml.prediction_60d,
      ml_prediction_90d:ml.prediction_90d,
      ml_recommendation:ml.recommendation,
      ml_predicted_date:ml.predicted_zombie_date,
      ml_factors:ml.factors,
    };
  });
  MOCK_EDGES.forEach(([a,b])=>{
    if(arr[a]&&arr[b])arr[a].conns.push(arr[b].id);
  });
  return arr;
}

function Badge({status}){
  const cfg={
    active:[C.green,"●"],zombie:[C.red,"☠"],
    deprecated:[C.orange,"▲"],honeypot:[C.neon,"⬡"],
    quarantined:[C.amber,"⊗"],
  };
  const[c,icon]=cfg[status]||cfg.active;
  return(
    <span style={{
      display:"inline-flex",alignItems:"center",gap:4,
      padding:"2px 9px",borderRadius:3,
      fontFamily:"'JetBrains Mono',monospace",
      fontSize:9,fontWeight:700,letterSpacing:1,
      background:`${c}18`,color:c,border:`1px solid ${c}44`,
      textTransform:"uppercase",
    }}>{icon} {status}</span>
  );
}

function RiskBar({v,wide}){
  const c=v>=70?C.red:v>=45?C.orange:C.green;
  return(
    <div style={{display:"flex",alignItems:"center",gap:8}}>
      <div style={{width:wide?100:66,height:3,background:C.bg,borderRadius:2,overflow:"hidden"}}>
        <div style={{width:`${v}%`,height:"100%",background:c,
          boxShadow:`0 0 6px ${c}`,borderRadius:2,transition:"width .6s"}}/>
      </div>
      <span style={{fontFamily:"'JetBrains Mono',monospace",
        fontSize:11,fontWeight:700,color:c,minWidth:24}}>{v}</span>
    </div>
  );
}

function MLBar({v,label}){
  const c=v>=75?C.red:v>=50?C.orange:v>=25?C.amber:C.green;
  return(
    <div>
      {label&&<div style={{fontFamily:"'JetBrains Mono',monospace",
        fontSize:7,color:C.dim,letterSpacing:1,marginBottom:3}}>{label}</div>}
      <div style={{display:"flex",alignItems:"center",gap:8}}>
        <div style={{flex:1,height:4,background:C.bg,borderRadius:2,overflow:"hidden"}}>
          <div style={{width:`${v}%`,height:"100%",background:c,
            boxShadow:`0 0 5px ${c}`,borderRadius:2,transition:"width .8s"}}/>
        </div>
        <span style={{fontFamily:"'JetBrains Mono',monospace",
          fontSize:10,fontWeight:700,color:c,minWidth:32,textAlign:"right"}}>{v}%</span>
      </div>
    </div>
  );
}

function Btn({children,variant="ghost",sm,lg,onClick,disabled,full,style:sx={}}){
  const base={
    display:"inline-flex",alignItems:"center",justifyContent:"center",gap:7,
    cursor:disabled?"not-allowed":"pointer",border:"none",borderRadius:4,
    fontFamily:"'Rajdhani',sans-serif",fontWeight:600,letterSpacing:.5,
    transition:"all .18s",opacity:disabled?.35:1,whiteSpace:"nowrap",
    width:full?"100%":"auto",
    padding:lg?"11px 28px":sm?"5px 13px":"9px 20px",
    fontSize:lg?14:sm?11:13,
  };
  const vars={
    primary:{background:C.neon,color:C.bg,boxShadow:`0 0 24px ${C.neon}55`},
    danger:{background:`${C.red}1a`,color:C.red,border:`1px solid ${C.red}55`},
    success:{background:`${C.green}12`,color:C.green,border:`1px solid ${C.green}44`},
    warning:{background:`${C.amber}12`,color:C.amber,border:`1px solid ${C.amber}44`},
    plasma:{background:`${C.plasma}18`,color:"#cc88ff",border:`1px solid ${C.plasma}44`},
    ghost:{background:"transparent",color:C.muted,border:`1px solid ${C.border}`},
  };
  return(
    <button style={{...base,...vars[variant],...sx}}
      onClick={disabled?undefined:onClick}>{children}</button>
  );
}

function Panel({title,icon,meta,badge,accent,children}){
  return(
    <div style={{background:C.panel,border:`1px solid ${C.border}`,
      borderRadius:6,overflow:"hidden",marginBottom:18}}>
      <div style={{padding:"12px 20px",borderBottom:`1px solid ${C.border}`,
        display:"flex",alignItems:"center",gap:10,
        background:"rgba(0,0,0,.32)",position:"relative"}}>
        <div style={{position:"absolute",bottom:0,left:0,
          width:64,height:1,background:accent||C.neon,opacity:.6}}/>
        {icon&&<span style={{fontSize:15}}>{icon}</span>}
        <span style={{fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
          fontSize:13,letterSpacing:1,color:C.text,textTransform:"uppercase"}}>
          {title}
        </span>
        {meta&&<span style={{marginLeft:"auto",
          fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:C.dim}}>{meta}</span>}
        {badge&&<span style={{fontFamily:"'JetBrains Mono',monospace",
          fontSize:9,padding:"2px 7px",borderRadius:3,
          background:`${C.neon}14`,color:C.neon2,border:`1px solid ${C.neon}30`}}>{badge}</span>}
      </div>
      {children}
    </div>
  );
}

function SevBadge({sev}){
  const c=sev==="CRITICAL"?C.red:sev==="HIGH"?C.orange:sev==="MEDIUM"?C.amber:C.green;
  return(
    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
      fontWeight:700,padding:"2px 7px",borderRadius:3,letterSpacing:1,
      background:`${c}18`,color:c,border:`1px solid ${c}44`}}>{sev}</span>
  );
}
function Empty({icon="⬡",msg}){
  return(
    <div style={{textAlign:"center",padding:"56px 20px",
      fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.dim,letterSpacing:.5}}>
      <div style={{fontSize:36,opacity:.18,marginBottom:14}}>{icon}</div>
      {msg}
    </div>
  );
}

function Spin(){
  return<span style={{display:"inline-block",animation:"spin 1s linear infinite"}}>◌</span>;
}

function Typed({text,speed=8}){
  const[shown,setShown]=useState("");
  const[done,setDone]=useState(false);
  useEffect(()=>{
    setShown("");setDone(false);
    if(!text)return;
    let i=0;
    const t=setInterval(()=>{
      i++;setShown(text.slice(0,i));
      if(i>=text.length){clearInterval(t);setDone(true);}
    },speed);
    return()=>clearInterval(t);
  },[text]);
  return(
    <span>
      {shown}
      {!done&&<span style={{display:"inline-block",width:2,height:"1em",
        background:C.neon,marginLeft:2,animation:"blink .7s step-end infinite",
        verticalAlign:"text-bottom"}}/>}
    </span>
  );
}

function voiceAlert(msg){
  if(!("speechSynthesis" in window))return;
  window.speechSynthesis.cancel();
  const u=new SpeechSynthesisUtterance(msg);
  u.rate=0.88;u.pitch=0.75;u.volume=0.75;
  window.speechSynthesis.speak(u);
}

function BootScreen({onDone}){
  const[lines,setLines]=useState([]);
  const[pct,setPct]=useState(0);
  const[fade,setFade]=useState(false);
  const BOOT=[
    {t:0,  txt:"NECROS X AUTONOMOUS API DEFENSE SYSTEM v6.0",c:C.neon,bold:true},
    {t:200,txt:"Somaiya Vidyavihar University · IDEA 2.0 Hackathon",c:C.dim},
    {t:400,txt:"",c:C.dim},
    {t:500,txt:"[OK] Loading API Registry (TinyDB persistent store)...",c:C.green},
    {t:700,txt:"[OK] GradientBoosting ML model initialized (8 features)...",c:C.green},
    {t:900,txt:"[OK] Zombie classification engine ready...",c:C.green},
    {t:1100,txt:"[OK] Attack path visualization engine loaded...",c:C.green},
    {t:1300,txt:"[OK] Honeypot defense engine standby...",c:C.green},
    {t:1500,txt:"[OK] AI analyst (Claude claude-sonnet-4-5) online...",c:C.green},
    {t:1700,txt:"[OK] Hardware LED panel initialized...",c:C.green},
    {t:1900,txt:"[OK] Auto-defense engine armed...",c:C.green},
    {t:2100,txt:"",c:C.dim},
    {t:2200,txt:"[!!] 2 ZOMBIE APIs DETECTED IN REGISTRY",c:C.red,bold:true},
    {t:2400,txt:"[!!] THREAT LEVEL: CRITICAL — IMMEDIATE ACTION REQUIRED",c:C.red,bold:true},
    {t:2600,txt:"",c:C.dim},
    {t:2700,txt:"System armed. Launching defense dashboard...",c:C.neon,bold:true},
  ];
  useEffect(()=>{
    BOOT.forEach(b=>{
      setTimeout(()=>{
        setLines(l=>[...l,b]);
        setPct(p=>Math.min(p+Math.round(100/BOOT.length),100));
      },b.t);
    });
    setTimeout(()=>setFade(true),3200);
    setTimeout(()=>onDone(),3700);
  },[]);
  return(
    <div style={{position:"fixed",inset:0,background:C.bg,
      display:"flex",flexDirection:"column",alignItems:"center",
      justifyContent:"center",zIndex:9999,
      transition:"opacity .5s",opacity:fade?0:1}}>
      <div style={{width:"min(660px,90vw)"}}>
        <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:26,
          fontWeight:900,letterSpacing:6,color:C.neon,
          textShadow:`0 0 40px ${C.neon}`,
          marginBottom:28,textAlign:"center"}}>☠ NECROS X</div>
        <div style={{background:C.bg2,border:`1px solid ${C.border}`,
          borderRadius:6,padding:"18px 22px",minHeight:280,marginBottom:18}}>
          {lines.map((l,i)=>(
            <div key={i} style={{fontSize:10,letterSpacing:.4,marginBottom:3,
              color:l.c,fontWeight:l.bold?"700":"400",
              fontFamily:"'JetBrains Mono',monospace"}}>
              {l.txt||"\u00a0"}
            </div>
          ))}
          <span style={{display:"inline-block",width:2,height:12,background:C.neon,
            animation:"blink .6s step-end infinite",verticalAlign:"middle"}}/>
        </div>
        <div style={{height:3,background:C.bg2,borderRadius:2,
          overflow:"hidden",border:`1px solid ${C.border}`}}>
          <div style={{height:"100%",width:`${pct}%`,
            background:`linear-gradient(90deg,${C.neon2},${C.neon})`,
            boxShadow:`0 0 10px ${C.neon}`,transition:"width .3s",borderRadius:2}}/>
        </div>
        <div style={{textAlign:"right",marginTop:5,fontSize:9,
          color:C.dim,letterSpacing:2,
          fontFamily:"'JetBrains Mono',monospace"}}>{pct}% COMPLETE</div>
      </div>
    </div>
  );
}

function Graph({apis,onPick,picked}){
  const[nodes,setNodes]=useState([]);
  const[edges,setEdges]=useState([]);
  const[parts,setParts]=useState([]);
  const[tip,setTip]=useState(null);
  const nRef=useRef([]);const eRef=useRef([]);
  const animR=useRef();const partR=useRef();
  const W=760,H=440;
  useEffect(()=>{
    if(!apis.length)return;
    const LP={AUTH:[W*.35,H*.18],FINANCE:[W*.13,H*.55],
      DATA:[W*.67,H*.38],EVENTS:[W*.5,H*.76],
      ADMIN:[W*.24,H*.78],OPS:[W*.82,H*.68]};
    const idM={};
    const ns=apis.map(a=>{
      const[lx,ly]=LP[a.layer]||[W/2,H/2];
      const n={...a,x:lx+(Math.random()-.5)*55,y:ly+(Math.random()-.5)*45,vx:0,vy:0};
      idM[a.id]=n;return n;
    });
    const es=[];
    apis.forEach(a=>{
      const src=ns.find(n=>n.id===a.id);
      a.conns.forEach(tid=>{
        const dst=idM[tid];
        if(src&&dst)es.push({k:`${src.id}${dst.id}`,src,dst,
          zom:src.status==="zombie"||dst.status==="zombie"});
      });
    });
    nRef.current=ns;eRef.current=es;setEdges([...es]);
    setParts(es.map(e=>({eid:e.k,t:Math.random(),
      spd:.003+Math.random()*.005,zom:e.zom})));
    let tick=0;
    const sim=()=>{
      const a=nRef.current;
      for(let i=0;i<a.length;i++)
        for(let j=i+1;j<a.length;j++){
          const dx=a[j].x-a[i].x,dy=a[j].y-a[i].y;
          const d=Math.sqrt(dx*dx+dy*dy)||1,f=1900/(d*d);
          a[i].vx-=(dx/d)*f;a[i].vy-=(dy/d)*f;
          a[j].vx+=(dx/d)*f;a[j].vy+=(dy/d)*f;
        }
      eRef.current.forEach(({src,dst})=>{
        const dx=dst.x-src.x,dy=dst.y-src.y;
        const d=Math.sqrt(dx*dx+dy*dy)||1,f=(d-118)*.015;
        src.vx+=(dx/d)*f;src.vy+=(dy/d)*f;
        dst.vx-=(dx/d)*f;dst.vy-=(dy/d)*f;
      });
      a.forEach(n=>{
        n.vx+=(W/2-n.x)*.003;n.vy+=(H/2-n.y)*.003;
        n.x+=n.vx*.4;n.y+=n.vy*.4;n.vx*=.55;n.vy*=.55;
        n.x=clamp(n.x,40,W-40);n.y=clamp(n.y,32,H-32);
      });
      tick++;setNodes([...a]);
      if(tick<160)animR.current=requestAnimationFrame(sim);
    };
    animR.current=requestAnimationFrame(sim);
    return()=>{cancelAnimationFrame(animR.current);clearInterval(partR.current);};
  },[apis]);
  useEffect(()=>{
    if(!parts.length)return;
    partR.current=setInterval(()=>
      setParts(p=>p.map(x=>({...x,t:(x.t+x.spd)%1}))),50);
    return()=>clearInterval(partR.current);
  },[parts.length]);
  const gPt=p=>{
    const e=eRef.current.find(e=>e.k===p.eid);
    if(!e)return null;
    return{x:e.src.x+(e.dst.x-e.src.x)*p.t,
      y:e.src.y+(e.dst.y-e.src.y)*p.t,c:p.zom?C.red:C.neon};
  };
  const nr=n=>n.status==="zombie"||n.honeypot?21:n.status==="deprecated"?17:14;
  const lbl=p=>p.split("/").pop().slice(0,8);
  return(
    <div style={{position:"relative",background:"#010408",borderRadius:6,overflow:"hidden"}}>
      <div style={{position:"absolute",top:10,left:10,
        display:"flex",flexDirection:"column",gap:3,zIndex:5,pointerEvents:"none"}}>
        {[["NODES",nodes.length,C.neon],["EDGES",edges.length,C.neon],
          ["ZOMBIES",nodes.filter(n=>n.status==="zombie").length,C.red],
          ["HONEYPOTS",nodes.filter(n=>n.honeypot).length,C.green],
          ["ML AT-RISK",nodes.filter(n=>(n.ml_zombie_probability||0)>=50&&n.status==="active").length,C.amber],
        ].map(([k,v,c])=>(
          <div key={k} style={{fontFamily:"'JetBrains Mono',monospace",
            fontSize:8,color:C.dim,background:"rgba(1,4,8,.92)",
            border:`1px solid ${C.border}`,padding:"2px 8px",borderRadius:3,letterSpacing:1}}>
            {k}<span style={{color:c,marginLeft:6}}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{position:"absolute",top:10,right:10,
        display:"flex",flexDirection:"column",gap:3,zIndex:5,
        pointerEvents:"none",alignItems:"flex-end"}}>
        {[["TOPOLOGY","FORCE-DIRECTED"],["PROTOCOL","REST/HTTPS"],
          ["ML","GRADIENT BOOST"],["PARTICLES","LIVE DATA FLOW"],
        ].map(([k,v])=>(
          <div key={k} style={{fontFamily:"'JetBrains Mono',monospace",
            fontSize:8,color:C.dim,background:"rgba(1,4,8,.92)",
            border:`1px solid ${C.border}`,padding:"2px 8px",borderRadius:3,letterSpacing:1}}>
            {k}<span style={{color:C.neon2,marginLeft:6}}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{position:"absolute",bottom:10,left:10,
        display:"flex",gap:10,background:"rgba(1,4,8,.92)",
        border:`1px solid ${C.border}`,padding:"6px 12px",
        borderRadius:4,zIndex:5,pointerEvents:"none"}}>
        {[[C.green,"Active"],[C.red,"Zombie"],
          [C.orange,"Deprecated"],[C.neon,"Honeypot"],[C.amber,"ML At-Risk"],
        ].map(([c,l])=>(
          <div key={l} style={{display:"flex",alignItems:"center",gap:5,
            fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:C.dim}}>
            <div style={{width:7,height:7,borderRadius:"50%",
              background:c,boxShadow:`0 0 4px ${c}`}}/>{l}
          </div>
        ))}
      </div>
      {tip&&(
        <div style={{position:"absolute",
          left:Math.min(tip.x+16,542),top:Math.max(tip.y-110,6),
          zIndex:20,background:"rgba(3,12,26,.97)",
          border:`1px solid ${C.edge}`,borderRadius:4,padding:"10px 14px",
          fontFamily:"'JetBrains Mono',monospace",fontSize:9,
          minWidth:200,pointerEvents:"none",
          boxShadow:"0 4px 28px rgba(0,0,0,.75)"}}>
          <div style={{color:C.neon,marginBottom:7,fontSize:8,
            borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
            {tip.path}
          </div>
          <div style={{fontSize:8,color:C.dim,marginBottom:6,fontStyle:"italic"}}>
            {tip.desc}
          </div>
          {[["STATUS",tip.status],["RISK",`${tip.risk||tip.risk_score||0}/100`],
            ["ML PROB",`${tip.ml_zombie_probability||0}%`],["LAYER",tip.layer],
            ["OWNER",tip.owner||"unknown"],
            ["CALLS/DAY",(tip.calls_per_day||0).toLocaleString()],
          ].map(([k,v])=>(
            <div key={k} style={{display:"flex",justifyContent:"space-between",
              gap:14,marginBottom:3,color:C.dim,fontSize:8}}>
              <span>{k}</span><span style={{color:C.text}}>{v}</span>
            </div>
          ))}
        </div>
      )}
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{display:"block"}}>
        <defs>
          <radialGradient id="gBg" cx="50%" cy="50%" r="60%">
            <stop offset="0%" stopColor="#071428"/>
            <stop offset="100%" stopColor="#010408"/>
          </radialGradient>
          <pattern id="gGrid" width="38" height="38" patternUnits="userSpaceOnUse">
            <path d="M38 0L0 0 0 38" fill="none" stroke="rgba(11,32,64,.5)" strokeWidth=".5"/>
          </pattern>
          {[["gfR",5],["gfG",3],["gfB",4],["gfO",3],["gfY",3]].map(([id,sd])=>(
            <filter key={id} id={id}>
              <feGaussianBlur stdDeviation={sd} result="b"/>
              <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          ))}
<marker id="mN" viewBox="0 0 8 6" refX="7" refY="3"
            markerWidth="5" markerHeight="5" orient="auto">
            <path d="M0 0L8 3L0 6z" fill="rgba(0,120,184,.6)"/>
          </marker>
          <marker id="mZ" viewBox="0 0 8 6" refX="7" refY="3"
            markerWidth="5" markerHeight="5" orient="auto">
            <path d="M0 0L8 3L0 6z" fill="rgba(255,26,60,.7)"/>
          </marker>
        </defs>
        <rect width={W} height={H} fill="url(#gBg)"/>
        <rect width={W} height={H} fill="url(#gGrid)"/>
        {[80,152,224].map(r=>(
          <circle key={r} cx={W/2} cy={H/2} r={r} fill="none"
            stroke="rgba(0,120,184,.025)" strokeWidth="1" strokeDasharray="4 10"/>
        ))}
        {edges.map(e=>(
          <g key={e.k}>
            {e.zom&&<line x1={e.src.x} y1={e.src.y} x2={e.dst.x} y2={e.dst.y}
              stroke="rgba(255,26,60,.08)" strokeWidth="6"/>}
            <line x1={e.src.x} y1={e.src.y} x2={e.dst.x} y2={e.dst.y}
              stroke={e.zom?"rgba(255,26,60,.4)":"rgba(0,120,184,.32)"}
              strokeWidth={e.zom?1.5:1} strokeDasharray={e.zom?"6 4":"none"}
              markerEnd={e.zom?"url(#mZ)":"url(#mN)"}/>
          </g>
        ))}
        {parts.map((p,i)=>{
          const pos=gPt(p);if(!pos)return null;
          return<circle key={i} cx={pos.x} cy={pos.y} r="2.3"
            fill={pos.c} opacity=".9"
            style={{filter:`drop-shadow(0 0 3px ${pos.c})`}}/>;
        })}
        {nodes.map(n=>{
          const col=sColor(n.status);
          const mlHigh=(n.ml_zombie_probability||0)>=50&&n.status==="active";
          const r=nr(n);const sel=picked===n.id;
          const filt=n.status==="zombie"?"url(#gfR)":n.honeypot?"url(#gfB)":
            n.status==="deprecated"?"url(#gfO)":mlHigh?"url(#gfY)":"url(#gfG)";
          const nodeCol=mlHigh?C.amber:col;
          return(
            <g key={n.id} transform={`translate(${n.x},${n.y})`}
              style={{cursor:"pointer"}}
              onClick={()=>onPick&&onPick(n.id)}
              onMouseEnter={()=>setTip({...n,x:n.x,y:n.y})}
              onMouseLeave={()=>setTip(null)}>
              {n.status==="zombie"&&!n.honeypot&&[1,2].map(i=>(
                <circle key={i} r={r+8*i} fill="none"
                  stroke="rgba(255,26,60,.14)" strokeWidth="1">
                  <animate attributeName="r"
                    values={`${r};${r+15*i};${r}`}
                    dur={`${1.7+i*.5}s`} repeatCount="indefinite"/>
                  <animate attributeName="opacity"
                    values=".55;0;.55" dur={`${1.7+i*.5}s`}
                    repeatCount="indefinite"/>
                </circle>
              ))}
              {mlHigh&&(
                <circle r={r+6} fill="none"
                  stroke="rgba(255,170,0,.2)" strokeWidth="1">
                  <animate attributeName="r"
                    values={`${r};${r+10};${r}`}
                    dur="2.2s" repeatCount="indefinite"/>
                  <animate attributeName="opacity"
                    values=".4;0;.4" dur="2.2s"
                    repeatCount="indefinite"/>
                </circle>
              )}
              {sel&&<circle r={r+10} fill="none"
                stroke={nodeCol} strokeWidth="1.5" opacity=".35"/>}
              <circle r={r} fill={`${nodeCol}16`}
                stroke={nodeCol} strokeWidth={sel?2.5:1.5} filter={filt}/>
              {n.honeypot
                ?<text textAnchor="middle" dominantBaseline="central"
                    fontSize="13">🍯</text>
                :<circle r={5} fill={nodeCol} opacity=".95"/>}
              <rect x={-16} y={r+4} width={32} height={11} rx="2"
                fill="rgba(0,0,0,.72)" stroke={nodeCol}
                strokeWidth=".5" opacity=".88"/>
              <text x={0} y={r+12} textAnchor="middle" fill={nodeCol}
                fontSize="6.5" fontFamily="'JetBrains Mono',monospace"
                letterSpacing=".3">
                {n.honeypot?"HONEYPOT":n.layer}
              </text>
              <text x={0} y={r+26} textAnchor="middle"
                fill="rgba(168,204,232,.6)" fontSize="7.5"
                fontFamily="'JetBrains Mono',monospace">
                {lbl(n.path)}
              </text>
              {(n.ml_zombie_probability||0)>0&&(
                <text x={0} y={r+38} textAnchor="middle"
                  fill={(n.ml_zombie_probability||0)>=75?C.red:
                    (n.ml_zombie_probability||0)>=50?C.amber:C.dim}
                  fontSize="7" fontFamily="'JetBrains Mono',monospace">
                  ML:{n.ml_zombie_probability}%
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function DemoBanner({step}){
  if(step===0||step>=5)return null;
  const steps=["Scan","Detect","Attack","Defend","Intel"];
  const hints=["","Select zombie endpoint ↓","Click ⚡ Simulate Attack",
    "Click 🍯 Deploy Honeypot","View Logs & AI tabs"];
  return(
    <div style={{background:"rgba(0,200,255,.05)",
      border:`1px solid rgba(0,200,255,.18)`,borderRadius:5,
      padding:"9px 16px",marginBottom:14,
      display:"flex",alignItems:"center",gap:14}}>
      <span style={{fontFamily:"'JetBrains Mono',monospace",
        fontSize:8,color:C.neon2,letterSpacing:2,flexShrink:0}}>DEMO FLOW</span>
      <div style={{display:"flex",alignItems:"center",flex:1,gap:0}}>
        {steps.map((s,i)=>(
          <span key={s} style={{display:"flex",alignItems:"center"}}>
            <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
              letterSpacing:.5,
              color:i<step?C.green:i===step?C.neon:C.dim,
              display:"flex",alignItems:"center",gap:4}}>
              <span style={{display:"inline-flex",alignItems:"center",
                justifyContent:"center",width:15,height:15,borderRadius:"50%",
                border:"1px solid currentColor",fontSize:7,fontWeight:700,flexShrink:0}}>
                {i<step?"✓":i+1}
              </span>{s}
            </span>
            {i<steps.length-1&&<span style={{color:C.border,margin:"0 7px",fontSize:10}}>›</span>}
          </span>
        ))}
      </div>
      <span style={{fontFamily:"'JetBrains Mono',monospace",
        fontSize:8,color:C.amber,flexShrink:0}}>▶ {hints[step]}</span>
    </div>
  );
}

function AlertCenter({alerts,onAck}){
  if(!alerts.length)return<Empty icon="🔔" msg="No active alerts. System nominal."/>;
  const sorted=[...alerts].sort((a,b)=>{
    const s={CRITICAL:0,HIGH:1,MEDIUM:2,INFO:3};
    return(s[a.sev]||4)-(s[b.sev]||4);
  });
  const c=s=>s==="CRITICAL"?C.red:s==="HIGH"?C.orange:s==="MEDIUM"?C.amber:C.neon;
  return(
    <div style={{display:"flex",flexDirection:"column",gap:8,padding:"14px 16px"}}>
      {sorted.map((al,i)=>(
        <div key={i} style={{display:"flex",alignItems:"flex-start",gap:12,
          padding:"10px 14px",borderRadius:4,
          background:al.ack?"rgba(0,0,0,.2)":`${c(al.sev)}06`,
          border:`1px solid ${al.ack?C.border:c(al.sev)+"33"}`,
          opacity:al.ack?.45:1,transition:"all .3s"}}>
          <div style={{width:8,height:8,borderRadius:"50%",
            background:c(al.sev),flexShrink:0,marginTop:5,
            boxShadow:al.ack?"none":`0 0 6px ${c(al.sev)}`}}/>
          <div style={{flex:1}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <SevBadge sev={al.sev}/>
              <span style={{fontFamily:"'JetBrains Mono',monospace",
                fontSize:8,color:C.dim}}>{al.ts||""}</span>
              <span style={{marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",
                fontSize:8,color:C.dim,letterSpacing:1}}>{al.type}</span>
            </div>
            <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,
              lineHeight:1.6,color:al.ack?C.dim:C.text,letterSpacing:.3}}>{al.msg}</div>
          </div>
          {!al.ack&&(
            <button onClick={()=>onAck&&onAck(i)}
              style={{background:"transparent",border:`1px solid ${C.border}`,
                borderRadius:3,padding:"3px 9px",cursor:"pointer",
                fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                color:C.dim,flexShrink:0}}>ACK</button>
          )}
        </div>
      ))}
    </div>
  );
}

function ThreatIntel(){
  const[data,setData]=useState(null);
  const[loading,setLoading]=useState(false);
  useEffect(()=>{
    setLoading(true);
    fetch(`${API}/threats`)
      .then(r=>r.ok?r.json():Promise.reject())
      .then(d=>setData(d))
      .catch(()=>setData({
        feed:[
          {id:uid(),actor:"APT-29",sev:"CRITICAL",ts:ts(),
           title:"Active campaign on legacy auth endpoints",
           iocs:["185.220.101.0/24","jwt-bypass-kit-v3"],
           ttps:["T1078","T1190","T1110"]},
          {id:uid(),actor:"Mass Scanner",sev:"HIGH",ts:ts(),
           title:"ZGrab2 API sweep — 847 targets globally",
           iocs:["194.165.16.0/24","ZGrab/2.x"],ttps:["T1595","T1046"]},
          {id:uid(),actor:"Lazarus Group",sev:"HIGH",ts:ts(),
           title:"SSRF kit targeting cloud metadata",
           iocs:["169.254.169.254"],ttps:["T1090","T1190"]},
          {id:uid(),actor:"FIN7",sev:"MEDIUM",ts:ts(),
           title:"47M credential combo on finance APIs",
           iocs:["combo-2024-Q4.txt"],ttps:["T1110.004"]},
        ],
        stats:{active_campaigns:4,iocs_tracked:1247,
               nations_involved:6,last_updated:ts()},
      }))
      .finally(()=>setLoading(false));
  },[]);
  if(loading)return(
    <div style={{padding:40,textAlign:"center",color:C.dim,
      fontFamily:"'JetBrains Mono',monospace",fontSize:10}}>
      <Spin/> Loading...
    </div>
  );
  if(!data)return<Empty icon="🌐" msg="No threat data."/>;
  const sc=s=>s==="CRITICAL"?C.red:s==="HIGH"?C.orange:C.amber;
  return(
    <div style={{padding:"14px 16px"}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",
        gap:10,marginBottom:16}}>
        {[["Active Campaigns",data.stats.active_campaigns,C.red],
          ["IOCs Tracked",data.stats.iocs_tracked,C.neon],
          ["Nations",data.stats.nations_involved||6,C.orange],
        ].map(([k,v,c])=>(
          <div key={k} style={{background:C.bg,border:`1px solid ${C.border}`,
            borderRadius:4,padding:"10px 14px"}}>
            <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
              color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>{k}</div>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:22,
              fontWeight:900,color:c}}>{v}</div>
          </div>
        ))}
      </div>
      <div style={{display:"flex",flexDirection:"column",gap:10}}>
        {data.feed.map(item=>(
          <div key={item.id} style={{background:`${sc(item.sev)}06`,
            border:`1px solid ${sc(item.sev)}30`,borderRadius:4,
            padding:"12px 16px",position:"relative",overflow:"hidden"}}>
            <div style={{position:"absolute",top:0,left:0,
              width:2,height:"100%",background:sc(item.sev)}}/>
            <div style={{paddingLeft:12}}>
              <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
                <SevBadge sev={item.sev}/>
                <span style={{fontFamily:"'JetBrains Mono',monospace",
                  fontSize:9,color:C.neon2}}>{item.actor}</span>
                <span style={{marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",
                  fontSize:8,color:C.dim}}>{item.ts}</span>
              </div>
              <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:14,
                fontWeight:600,color:C.text,marginBottom:8}}>{item.title}</div>
              <div style={{marginBottom:6}}>
                <span style={{fontFamily:"'JetBrains Mono',monospace",
                  fontSize:7,color:C.dim,letterSpacing:1,marginRight:8}}>IOCs:</span>
                {item.iocs.map((ioc,i)=>(
                  <span key={i} style={{fontFamily:"'JetBrains Mono',monospace",
                    fontSize:8,padding:"2px 7px",borderRadius:3,marginRight:5,
                    background:"rgba(0,0,0,.4)",color:C.dim,
                    border:`1px solid ${C.border}`}}>{ioc}</span>
                ))}
              </div>
              {item.ttps&&(
                <div>
                  <span style={{fontFamily:"'JetBrains Mono',monospace",
                    fontSize:7,color:C.dim,letterSpacing:1,marginRight:8}}>
                    MITRE ATT&CK:</span>
                  {item.ttps.map((t,i)=>(
                    <span key={i} style={{fontFamily:"'JetBrains Mono',monospace",
                      fontSize:8,padding:"2px 7px",borderRadius:3,marginRight:5,
                      background:`${C.neon}0a`,color:C.neon2,
                      border:`1px solid ${C.neon}20`}}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function OWASPPanel({apis}){
  const OWASP=[
    {id:"API1",name:"Broken Object Level Authorization"},
    {id:"API2",name:"Broken Authentication"},
    {id:"API3",name:"Broken Object Property Level Auth"},
    {id:"API4",name:"Unrestricted Resource Consumption"},
    {id:"API5",name:"Broken Function Level Authorization"},
    {id:"API6",name:"Unrestricted Access to Business Flows"},
    {id:"API7",name:"Server-Side Request Forgery"},
    {id:"API8",name:"Security Misconfiguration"},
    {id:"API9",name:"Improper Inventory Management"},
    {id:"API10",name:"Unsafe Consumption of APIs"},
  ];
  const triggered=new Set();
  apis.forEach(a=>{
    if(!a.auth){triggered.add("API1");triggered.add("API2");}
    if(a.status==="zombie"||a.status==="deprecated")triggered.add("API9");
    if(!a.enc)triggered.add("API8");
    (a.owasp_flags||[]).forEach(f=>triggered.add(f));
  });
  return(
    <div style={{padding:"14px 16px"}}>
      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
        color:C.dim,letterSpacing:2,marginBottom:14,textTransform:"uppercase"}}>
        OWASP API Security Top 10 — 2023
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
        {OWASP.map(item=>{
          const hit=triggered.has(item.id);
          return(
            <div key={item.id} style={{display:"flex",alignItems:"center",gap:10,
              padding:"8px 12px",borderRadius:4,
              background:hit?`${C.red}08`:`${C.green}05`,
              border:`1px solid ${hit?C.red+"30":C.green+"20"}`}}>
              <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:10,
                fontWeight:700,color:hit?C.red:C.green,minWidth:38}}>{item.id}</div>
              <div style={{flex:1}}>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                  color:hit?C.text:C.dim,letterSpacing:.3,lineHeight:1.4}}>{item.name}</div>
              </div>
              <div style={{width:8,height:8,borderRadius:"50%",
                background:hit?C.red:C.green,flexShrink:0,
                boxShadow:`0 0 4px ${hit?C.red:C.green}`}}/>
            </div>
          );
        })}
      </div>
      <div style={{marginTop:14,display:"flex",gap:20,
        fontFamily:"'JetBrains Mono',monospace",fontSize:9}}>
        <span style={{color:C.red}}>● {triggered.size} EXPOSED</span>
        <span style={{color:C.green}}>● {10-triggered.size} CLEAR</span>
      </div>
    </div>
  );
}
function RiskChart({apis}){
  if(!apis.length)return<Empty icon="◈" msg="Scan to see distribution."/>;
  const buckets={
    "0–30":{count:0,color:C.green},"31–60":{count:0,color:C.amber},
    "61–80":{count:0,color:C.orange},"81–100":{count:0,color:C.red},
  };
  apis.forEach(a=>{
    const r=a.risk||a.risk_score||0;
    if(r<=30)buckets["0–30"].count++;
    else if(r<=60)buckets["31–60"].count++;
    else if(r<=80)buckets["61–80"].count++;
    else buckets["81–100"].count++;
  });
  const maxB=Math.max(...Object.values(buckets).map(b=>b.count));
  return(
    <div style={{padding:"14px 20px"}}>
      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
        color:C.dim,letterSpacing:2,marginBottom:14}}>RISK SCORE DISTRIBUTION</div>
      <div style={{display:"flex",alignItems:"flex-end",gap:12,height:90,marginBottom:12}}>
        {Object.entries(buckets).map(([lbl,b])=>(
          <div key={lbl} style={{flex:1,display:"flex",flexDirection:"column",
            alignItems:"center",gap:6}}>
            <div style={{fontFamily:"'JetBrains Mono',monospace",
              fontSize:10,fontWeight:700,color:b.color}}>{b.count}</div>
            <div style={{width:"100%",background:C.bg,borderRadius:2,
              overflow:"hidden",height:60,display:"flex",alignItems:"flex-end"}}>
              <div style={{width:"100%",
                height:`${maxB>0?(b.count/maxB)*100:0}%`,
                background:b.color,opacity:.85,transition:"height .8s",
                borderRadius:"2px 2px 0 0",boxShadow:`0 0 8px ${b.color}44`}}/>
            </div>
            <div style={{fontFamily:"'JetBrains Mono',monospace",
              fontSize:7,color:C.dim,letterSpacing:.5}}>{lbl}</div>
          </div>
        ))}
      </div>
      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
        color:C.dim,letterSpacing:2,marginTop:16,marginBottom:10}}>
        AVERAGE RISK BY LAYER
      </div>
      {["AUTH","DATA","FINANCE","EVENTS","ADMIN","OPS"].map(layer=>{
        const la=apis.filter(a=>a.layer===layer);
        if(!la.length)return null;
        const avg=Math.round(la.reduce((s,a)=>s+(a.risk||a.risk_score||0),0)/la.length);
        const c=avg>=70?C.red:avg>=45?C.orange:C.green;
        return(
          <div key={layer} style={{display:"flex",alignItems:"center",gap:10,marginBottom:7}}>
            <span style={{fontFamily:"'JetBrains Mono',monospace",
              fontSize:8,color:C.dim,letterSpacing:1,minWidth:54}}>{layer}</span>
            <div style={{flex:1,height:4,background:C.bg,borderRadius:2,overflow:"hidden"}}>
              <div style={{width:`${avg}%`,height:"100%",background:c,
                boxShadow:`0 0 4px ${c}`,borderRadius:2,transition:"width .8s"}}/>
            </div>
            <span style={{fontFamily:"'JetBrains Mono',monospace",
              fontSize:10,fontWeight:700,color:c,minWidth:24}}>{avg}</span>
          </div>
        );
      })}
    </div>
  );
}

function AIAnalyst({apis,selectedApiId}){
  const[msgs,setMsgs]=useState([{
    role:"ai",
    text:"NECROS AI v6.0 online. GradientBoosting ML + Claude claude-sonnet-4-5. I have analyzed your API surface and ML predictions. Ask me about zombie APIs, future predictions, attack paths, or remediation.",
  }]);
  const[input,setInput]=useState("");
  const[busy,setBusy]=useState(false);
  const scrollRef=useRef();
  const suggestions=[
    "Which APIs will become zombies in 90 days?",
    "What is the highest risk endpoint?",
    "Explain the attack path from legacy-auth",
    "How does the ML prediction engine work?",
    "What should I fix first?",
    "How do honeypots help us win?",
  ];
  useEffect(()=>{
    if(scrollRef.current)
      scrollRef.current.scrollTop=scrollRef.current.scrollHeight;
  },[msgs]);
  const send=useCallback(async(q)=>{
    const question=q||input.trim();
    if(!question||busy)return;
    setInput("");
    setMsgs(m=>[...m,{role:"user",text:question}]);
    setBusy(true);
    try{
      const r=await fetch(`${API}/ai/analyze`,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({question,api_id:selectedApiId||undefined}),
      });
      if(r.ok){
        const d=await r.json();
        setMsgs(m=>[...m,{role:"ai",text:d.answer,model:d.powered_by}]);
      }else throw new Error();
    }catch{
      const lo=question.toLowerCase();
      const zs=apis.filter(a=>a.status==="zombie");
      const avg=apis.length?Math.round(apis.reduce((s,a)=>s+a.risk,0)/apis.length):0;
      const mlHigh=apis.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active")
        .sort((a,b)=>(b.ml_zombie_probability||0)-(a.ml_zombie_probability||0));
      let ans="";
      if(lo.includes("predict")||lo.includes("future")||lo.includes("ml")||
         lo.includes("become")||lo.includes("90")||lo.includes("30")){
        ans="## AI Zombie Prediction Engine\n\n**Model:** GradientBoosting (8 features)\n\n"
          +"**Features:** calls_per_day, inactivity_days, auth, enc, layer_risk, "
          +"method_count, estimated_age, usage_drop_rate\n\n**Current predictions:**\n";
        (mlHigh.length?mlHigh:apis).slice(0,5).forEach(a=>{
          ans+=`• \`${a.path}\` — **${a.ml_zombie_probability||0}%** | `
            +`30d:${a.ml_prediction_30d||0}% | 90d:${a.ml_prediction_90d||0}%\n`;
        });
        ans+="\n**Key value:** 90-day early warning before APIs become threats.\n**OWASP:** API9:2023";
      }else if(lo.includes("attack path")||lo.includes("lateral")||lo.includes("chain")){
        ans="## Attack Path Analysis\n\n**Entry → Pivot → Escalate → Exfiltrate:**\n\n"
          +"`/api/v1/legacy-auth` (zombie entry)\n→ `/api/v2/users/profile` (pivot)\n"
          +"→ `/api/v2/payments/charge` (financial reach)\n→ `/api/v1/export/csv` (exfil)\n\n"
          +"**Financial exposure: YES** — payment APIs reachable in 4 hops.\n\n"
          +"**Fix:** Honeypot on zombie breaks the chain at entry point.\n**OWASP:** API1+API2+API7";
      }else if(lo.includes("zombie")||lo.includes("legacy")){
        ans=`## Zombie API Analysis — URGENCY: CRITICAL\n\n**${zs.length} zombies:**\n`;
        zs.forEach(z=>{ans+=`• \`${z.path}\` — Risk:${z.risk}/100 | `
          +`${z.days}d inactive | ML:${z.ml_zombie_probability||0}%\n`;});
        ans+="\n**Fix:** 1. Honeypot → 2. Rotate creds → 3. Firewall disable\n**OWASP:** API9:2023";
      }else if(lo.includes("fix")||lo.includes("first")||lo.includes("priority")){
        ans=`## Priority Remediation\n\nAvg Risk: ${avg}/100\n\n`
          +`TODAY: Honeypots on ${zs.length} zombie APIs\n`
          +"48 HRS: Enable auth on all endpoints (+35 pts)\n"
          +"1 WEEK: Enforce TLS across all APIs (+25 pts)\n\n"
          +"**ML at-risk (monitor these):**\n"
          +mlHigh.slice(0,3).map(a=>`• ${a.path} — ${a.ml_zombie_probability}%`).join("\n");
      }else if(lo.includes("honeypot")||lo.includes("trap")){
        ans="## Honeypot Defense\n\n**Rule:** Deploy honeypot BEFORE disabling zombie.\n\n"
          +"**Captures:** Attacker IPs, tool signatures, credentials, payloads\n"
          +"**Auto-defend:** Deploys all honeypots simultaneously — zero manual work.\n"
          +"**Average dwell time: 47 minutes of free threat intelligence.**";
      }else{
        ans=`## NECROS X Summary\n\nThreat: ${'CRITICAL' if avg>60 else 'HIGH' if avg>40 else 'MEDIUM'}\n`
          +`• ${apis.length} APIs | ${zs.length} zombies | ${mlHigh.length} ML at-risk\n`
          +`• Avg risk: ${avg}/100\n\nAsk about: ML predictions, zombies, attack paths, honeypots.`;
      }
      setMsgs(m=>[...m,{role:"ai",text:ans,model:"NECROS-AI + ML Engine"}]);
    }
    setBusy(false);
  },[input,busy,apis,selectedApiId]);
  return(
    <div style={{display:"flex",flexDirection:"column",height:"100%"}}>
      <div ref={scrollRef} style={{flex:1,overflowY:"auto",padding:"14px 16px",
        display:"flex",flexDirection:"column",gap:12,minHeight:0}}>
        {msgs.map((m,i)=>(
          <div key={i} style={{display:"flex",
            justifyContent:m.role==="user"?"flex-end":"flex-start",gap:10}}>
            {m.role==="ai"&&(
              <div style={{width:28,height:28,borderRadius:4,flexShrink:0,
                display:"flex",alignItems:"center",justifyContent:"center",
                background:`${C.plasma}18`,border:`1px solid ${C.plasma}44`,
                color:"#cc88ff",fontFamily:"'Orbitron',sans-serif",
                fontSize:10,fontWeight:900,marginTop:2}}>N</div>
            )}
            <div style={{maxWidth:"82%",
              background:m.role==="user"?`${C.neon}12`:C.bg3,
              border:`1px solid ${m.role==="user"?C.neon2+"44":C.border}`,
              borderRadius:m.role==="user"?"8px 2px 8px 8px":"2px 8px 8px 8px",
              padding:"10px 14px",fontFamily:"'JetBrains Mono',monospace",
              fontSize:10,lineHeight:1.85,color:C.text,whiteSpace:"pre-wrap"}}>
              {i===msgs.length-1&&m.role==="ai"&&!busy
                ?<Typed text={m.text} speed={6}/>:m.text}
              {m.model&&(
                <div style={{marginTop:7,fontSize:7,color:C.dim,letterSpacing:1,
                  borderTop:`1px solid ${C.border}`,paddingTop:5}}>◈ {m.model}</div>
              )}
            </div>
            {m.role==="user"&&(
              <div style={{width:28,height:28,borderRadius:4,flexShrink:0,
                display:"flex",alignItems:"center",justifyContent:"center",
                background:`${C.muted}18`,border:`1px solid ${C.border}`,
                color:C.muted,fontSize:8,fontFamily:"'JetBrains Mono',monospace",
                marginTop:2,fontWeight:700}}>YOU</div>
            )}
          </div>
        ))}
        {busy&&(
          <div style={{display:"flex",gap:10,alignItems:"flex-start"}}>
            <div style={{width:28,height:28,borderRadius:4,display:"flex",
              alignItems:"center",justifyContent:"center",
              background:`${C.plasma}18`,border:`1px solid ${C.plasma}44`,
              color:"#cc88ff",fontFamily:"'Orbitron',sans-serif",
              fontSize:10,fontWeight:900}}>N</div>
            <div style={{background:C.bg3,border:`1px solid ${C.border}`,
              borderRadius:"2px 8px 8px 8px",padding:"12px 16px",
              display:"flex",gap:5,alignItems:"center"}}>
              {[0,1,2].map(i=>(
                <div key={i} style={{width:5,height:5,borderRadius:"50%",
                  background:C.neon,
                  animation:`bounce .8s ${i*.15}s ease-in-out infinite`}}/>
              ))}
            </div>
          </div>
        )}
      </div>
      {msgs.length<=2&&(
        <div style={{padding:"0 16px 10px",display:"flex",flexWrap:"wrap",gap:6}}>
          {suggestions.map(s=>(
            <button key={s} onClick={()=>send(s)}
              style={{background:C.bg3,border:`1px solid ${C.border}`,
                borderRadius:4,padding:"5px 11px",cursor:"pointer",
                fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                color:C.dim,letterSpacing:.3,transition:"all .15s"}}
              onMouseEnter={e=>{e.target.style.borderColor=C.neon2;e.target.style.color=C.neon;}}
              onMouseLeave={e=>{e.target.style.borderColor=C.border;e.target.style.color=C.dim;}}>
              {s}
            </button>
          ))}
        </div>
 )}
      <div style={{padding:"10px 16px",borderTop:`1px solid ${C.border}`,
        display:"flex",gap:8,alignItems:"center"}}>
        <input value={input} onChange={e=>setInput(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&send()}
          placeholder="Ask NECROS AI about predictions, zombies, attack paths..."
          style={{flex:1,background:C.bg,border:`1px solid ${C.border}`,
            borderRadius:4,padding:"8px 12px",outline:"none",
            fontFamily:"'JetBrains Mono',monospace",fontSize:10,
            color:C.neon,caretColor:C.neon}}/>
        <Btn variant="plasma" sm onClick={()=>send()} disabled={busy||!input.trim()}>
          {busy?<Spin/>:"SEND"}
        </Btn>
      </div>
    </div>
  );
}

function Terminal({apis,onScan,target}){
  const[history,setHistory]=useState([{
    type:"banner",
    text:"NECROS X Terminal v6.0\nGradientBoosting ML · API Registry · Auto-Defense\nType 'help' for commands",
  }]);
  const[input,setInput]=useState("");
  const[cmdHist,setCmdHist]=useState([]);
  const[cmdIdx,setCmdIdx]=useState(-1);
  const[busy,setBusy]=useState(false);
  const scrollRef=useRef();const inputRef=useRef();
  useEffect(()=>{
    if(scrollRef.current)scrollRef.current.scrollTop=scrollRef.current.scrollHeight;
  },[history]);
  const run=useCallback(async(rawCmd)=>{
    const cmd=rawCmd.trim();
    if(!cmd)return;
    setInput("");setCmdHist(h=>[cmd,...h]);setCmdIdx(-1);
    setHistory(h=>[...h,{type:"cmd",text:`necros@x:~$ ${cmd}`}]);
    setBusy(true);
    try{
      const r=await fetch(`${API}/terminal`,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({command:cmd}),
      });
      if(r.ok){
        const d=await r.json();
        if(d.clear){
          setHistory([{type:"banner",text:"NECROS X Terminal v6.0\nType 'help'"}]);
        }else if(d.output!==undefined&&d.output){
          setHistory(h=>[...h,{type:"out",text:d.output}]);
        }
        if(d.action==="scan")onScan&&onScan(d.target);
      }else throw new Error();
    }catch{
      const lo=cmd.toLowerCase().trim();
      const parts=lo.split(" ");const base=parts[0];const args=parts.slice(1);
      if(base==="clear"){
        setHistory([{type:"banner",text:"NECROS X Terminal v6.0\nType 'help'"}]);
      }else if(base==="help"){
        setHistory(h=>[...h,{type:"out",text:
          "NECROS X Terminal v6.0\n"+"━".repeat(40)+"\n"
          +"  scan <url>      Scan API surface\n"
          +"  apis            List all APIs (with ML%)\n"
          +"  zombies         Show zombie APIs\n"
          +"  predict         ML predictions all\n"
          +"  predict <id>    ML prediction single\n"
          +"  attack <id>     Simulate attack\n"
          +"  honeypot <id>   Deploy honeypot\n"
          +"  autodefend      Auto-honeypot all zombies\n"
          +"  paths           Attack path visualization\n"
          +"  stats           System statistics\n"
          +"  alerts          Active alerts\n"
          +"  threats         Threat intel feed\n"
          +"  risk <id>       Risk breakdown\n"
          +"  history         Scan history\n"
          +"  hw test         Test LED hardware\n"
          +"  clear           Clear terminal\n"
          +"━".repeat(40)}]);
      }else if(base==="apis"){
        if(!apis.length){
          setHistory(h=>[...h,{type:"err",text:"No APIs. Run: scan <url>"}]);
        }else{
          const lines=["ID       PATH                    STATUS      RISK  ML%","─".repeat(58)];
          apis.forEach(a=>{
            lines.push(`${a.id.padEnd(9)}${a.path.slice(0,22).padEnd(23)}`
              +`${a.status.padEnd(12)}${a.risk.toString().padEnd(6)}`
              +`${(a.ml_zombie_probability||0).toFixed(0)}%`);
          });
          setHistory(h=>[...h,{type:"out",text:lines.join("\n")}]);
        }
      }else if(base==="zombies"){
        const zs=apis.filter(a=>a.status==="zombie");
        if(!zs.length){
          setHistory(h=>[...h,{type:"out",text:"No zombies. System clean."}]);
        }else{
          const lines=["☠ ZOMBIE APIs:","─".repeat(54)];
          zs.forEach(z=>{
            lines.push(`  ${z.id} | ${z.path}`);
            lines.push(`  Risk:${z.risk}/100 | Inactive:${z.days}d`
              +` | ML:${(z.ml_zombie_probability||0).toFixed(0)}%`);
          });
          setHistory(h=>[...h,{type:"err",text:lines.join("\n")}]);
        }
      }else if(base==="predict"){
        if(args.length){
          const aid=args[0].toUpperCase();
          const api=apis.find(a=>a.id===aid);
          if(!api){
            setHistory(h=>[...h,{type:"err",text:`API ${aid} not found.`}]);
          }else{
            const p=mlPredict(api);
            setHistory(h=>[...h,{type:"out",text:
              `ML PREDICTION: ${api.path}\n${"─".repeat(50)}\n`
              +`Zombie Probability: ${p.zombie_probability}%\n`
              +`Risk Level:         ${p.risk_level}\n`
              +`30-day forecast:    ${p.prediction_30d}%\n`
              +`60-day forecast:    ${p.prediction_60d}%\n`
              +`90-day forecast:    ${p.prediction_90d}%\n`
              +`Est. zombie date:   ${p.predicted_zombie_date}\n`
              +`${"─".repeat(50)}\n${p.recommendation}`}]);
          }
        }else{
          const sorted=[...apis].sort((a,b)=>
            (b.ml_zombie_probability||0)-(a.ml_zombie_probability||0));
          const lines=["ML PREDICTIONS:","─".repeat(62),
            `${"PATH".padEnd(28)}${"PROB".padStart(6)}${"30D".padStart(6)}`
            +`${"60D".padStart(6)}${"90D".padStart(6)}  LEVEL`,"─".repeat(62)];
          sorted.slice(0,8).forEach(a=>{
            lines.push(`${a.path.slice(0,27).padEnd(28)}`
              +`${(a.ml_zombie_probability||0).toFixed(1).padStart(5)}%`
              +`${(a.ml_prediction_30d||0).toFixed(1).padStart(5)}%`
              +`${(a.ml_prediction_60d||0).toFixed(1).padStart(5)}%`
              +`${(a.ml_prediction_90d||0).toFixed(1).padStart(5)}%`
              +`  ${a.ml_risk_level||"LOW"}`);
          });
          setHistory(h=>[...h,{type:"out",text:lines.join("\n")}]);
        }
      }else if(base==="stats"){
        const zc=apis.filter(a=>a.status==="zombie").length;
        const avg=apis.length?Math.round(apis.reduce((s,a)=>s+a.risk,0)/apis.length):0;
        const mlAt=apis.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active").length;
        setHistory(h=>[...h,{type:"out",text:
          `NECROS X v6.0\n${"─".repeat(32)}\n`
          +`Total APIs:  ${apis.length}\nZombie APIs: ${zc}\n`
          +`ML At-Risk:  ${mlAt}\nAvg Risk:    ${avg}/100`}]);
      }else if(base==="autodefend"){
        let acted=[];
        apis.forEach(a=>{if(a.status==="zombie"&&!a.honeypot)acted.push(a.path);});
        setHistory(h=>[...h,{type:"out",text:
          `AUTO-DEFEND\n${"─".repeat(44)}\n`
          +`Honeypots: ${acted.length}\n`
          +acted.map(p=>`  ✓ ${p}`).join("\n")
          +(acted.length?"\nAll zombies now trapping attackers.":"\nNo targets.")}]);
      }else if(base==="paths"){
        const zs=apis.filter(a=>a.status==="zombie");
        if(!zs.length){
          setHistory(h=>[...h,{type:"out",text:"No zombie entry points."}]);
        }else{
          const lines=["ATTACK PATHS:","─".repeat(50)];
          zs.forEach(z=>{
            const chain=[z.path,...z.conns.slice(0,3).map(id=>{
              const a=apis.find(x=>x.id===id);return a?a.path:"?";
            })];
            lines.push(chain.map(p=>p.split("/").pop()).join(" → "));
            lines.push(`  Entry:${z.path} | Depth:${chain.length}`);
          });
          setHistory(h=>[...h,{type:"out",text:lines.join("\n")}]);
        }
      }else if(base==="scan"){
const t=args[0]||target;
        setHistory(h=>[...h,{type:"out",text:`Scanning ${t}...\nSee GUI for animation.`}]);
        onScan&&onScan(t);
      }else if(base==="threats"){
        setHistory(h=>[...h,{type:"out",text:
          "🌐 THREAT INTEL\n"+"─".repeat(44)+"\n"
          +"[CRITICAL] APT-29 — Legacy auth campaign\n"
          +"[HIGH]     Mass Scanner — ZGrab2 sweep\n"
          +"[HIGH]     Lazarus — SSRF cloud metadata\n"
          +"[MEDIUM]   FIN7 — 47M credential combo\n"
          +"─".repeat(44)+"\nActive: 4 | IOCs: 1,247"}]);
      }else if(base==="alerts"){
        setHistory(h=>[...h,{type:"out",text:"No alerts in offline mode."}]);
      }else if(base==="risk"&&args.length){
        const aid=args[0].toUpperCase();
        const api=apis.find(a=>a.id===aid);
        if(!api){
          setHistory(h=>[...h,{type:"err",text:`API ${aid} not found.`}]);
        }else{
          const lines=[`RISK: ${api.path}`,"─".repeat(50),
            `Score: ${api.risk}/100`,`ML:    ${(api.ml_zombie_probability||0).toFixed(1)}%`,
            `Owner: ${api.owner||"unknown"}`,"FACTORS:"];
          if(!api.auth)lines.push("  ✗ No Auth   +35 [API2]");
          if(!api.enc) lines.push("  ✗ No TLS    +25 [API8]");
          if(api.days>180)lines.push(`  ✗ ${api.days}d inactive +30 [API9]`);
          setHistory(h=>[...h,{type:"out",text:lines.join("\n")}]);
        }
      }else if(base==="attack"&&args.length){
        const aid=args[0].toUpperCase();
        const api=apis.find(a=>a.id===aid);
        if(!api){
          setHistory(h=>[...h,{type:"err",text:`API ${aid} not found.`}]);
        }else{
          const atk=MOCK_ATKS[rnd(0,MOCK_ATKS.length-1)];
          const out=api.honeypot?"TRAPPED":!api.auth?"BREACH":"BLOCKED";
          setHistory(h=>[...h,{type:"out",text:
            `⚡ ATTACK SIM\n${"─".repeat(44)}\n`
            +`Target: ${api.path}\nAttack: ${atk.type}\n`
            +`OWASP:  ${atk.owasp}\nCVE:    ${atk.cve}\n`
            +`${"─".repeat(44)}\nOUTCOME: ■ ${out}`}]);
        }
      }else if((base==="honeypot"||base==="hp")&&args.length){
        const aid=args[0].toUpperCase();
        const api=apis.find(a=>a.id===aid);
        if(!api){
          setHistory(h=>[...h,{type:"err",text:`API ${aid} not found.`}]);
        }else if(api.status==="active"){
          setHistory(h=>[...h,{type:"err",text:"Cannot convert active API."}]);
        }else{
          setHistory(h=>[...h,{type:"out",text:
            `🍯 HONEYPOT LIVE\n${"─".repeat(44)}\n`
            +`Target:   ${api.path}\nCaptured: ${rnd(1,4)} attackers\n`
            +`Intel:    ${MOCK_INTEL[rnd(0,MOCK_INTEL.length-1)]}`}]);
        }
      }else if(base==="hw"&&args[0]==="test"){
        setHistory(h=>[...h,{type:"out",
          text:"Hardware test triggered.\nGreen → Amber → Red sequence."}]);
      }else if(base==="history"){
        setHistory(h=>[...h,{type:"out",text:"Connect backend for scan history."}]);
      }else{
        setHistory(h=>[...h,{type:"err",
          text:`Unknown: '${cmd}'\nType 'help' for commands.`}]);
      }
    }
    setBusy(false);inputRef.current?.focus();
  },[apis,target,onScan]);
  const onKey=e=>{
    if(e.key==="Enter"){run(input);return;}
    if(e.key==="ArrowUp"){
      e.preventDefault();
      const ni=Math.min(cmdIdx+1,cmdHist.length-1);
      setCmdIdx(ni);if(cmdHist[ni])setInput(cmdHist[ni]);
    }
    if(e.key==="ArrowDown"){
      e.preventDefault();
      const ni=Math.max(cmdIdx-1,-1);
      setCmdIdx(ni);setInput(ni===-1?"":cmdHist[ni]||"");
    }
  };
  const typeColor=t=>t==="cmd"?C.neon:t==="err"?C.red:t==="banner"?C.amber:C.green;
  return(
    <div style={{background:"#010408",border:`1px solid ${C.border}`,
      borderRadius:6,overflow:"hidden",display:"flex",
      flexDirection:"column",height:"100%",
      fontFamily:"'JetBrains Mono',monospace"}}>
      <div style={{padding:"8px 16px",borderBottom:`1px solid ${C.border}`,
        display:"flex",alignItems:"center",gap:10,background:"rgba(0,0,0,.5)"}}>
        <div style={{display:"flex",gap:5}}>
          {[C.red,C.amber,C.green].map((c,i)=>(
            <div key={i} style={{width:10,height:10,borderRadius:"50%",
              background:c,opacity:.7}}/>
          ))}
        </div>
        <span style={{fontSize:10,color:C.dim,letterSpacing:2,marginLeft:4}}>
          NECROS X — TERMINAL v6.0
        </span>
        <span style={{marginLeft:"auto",fontSize:8,color:C.dim}}>necros@x:~</span>
      </div>
      <div ref={scrollRef} style={{flex:1,overflowY:"auto",padding:"12px 16px",
        display:"flex",flexDirection:"column",gap:4,minHeight:0}}
        onClick={()=>inputRef.current?.focus()}>
        {history.map((h,i)=>(
          <pre key={i} style={{fontFamily:"'JetBrains Mono',monospace",
            fontSize:10,lineHeight:1.6,color:typeColor(h.type),
            whiteSpace:"pre-wrap",wordBreak:"break-all",margin:0}}>{h.text}</pre>
        ))}
        <div style={{display:"flex",alignItems:"center",gap:6,marginTop:4}}>
          <span style={{fontSize:10,color:C.neon,whiteSpace:"nowrap"}}>necros@x:~$</span>
          <input ref={inputRef} value={input}
            onChange={e=>setInput(e.target.value)}
            onKeyDown={onKey} disabled={busy}
            style={{flex:1,background:"transparent",border:"none",outline:"none",
              fontFamily:"'JetBrains Mono',monospace",fontSize:10,
              color:C.green,caretColor:C.green}}
            autoFocus/>
          {busy&&<Spin/>}
        </div>
      </div>
    </div>
  );
}
function PagePredict({apis}){
  const[preds,setPreds]=useState([]);
  const[loading,setLoading]=useState(false);
  const[selPred,setSelPred]=useState(null);
  const sevC=s=>s==="CRITICAL"?C.red:s==="HIGH"?C.orange:s==="MEDIUM"?C.amber:C.green;
  const loadPreds=useCallback(async()=>{
    setLoading(true);
    try{
      const r=await fetch(`${API}/predict/all`);
      if(r.ok){const d=await r.json();setPreds(d.predictions||[]);}
      else throw new Error();
    }catch{
      const offline=apis.map(a=>({id:a.id,path:a.path,status:a.status,...mlPredict(a)}))
        .sort((a,b)=>b.zombie_probability-a.zombie_probability);
      setPreds(offline);
    }
    setLoading(false);
  },[apis]);
  useEffect(()=>{loadPreds();},[apis.length]);
  return(
    <div>
      <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:6,
        padding:"16px 20px",marginBottom:18,
        display:"grid",gridTemplateColumns:"1fr auto",gap:16,alignItems:"center"}}>
        <div>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:14,fontWeight:900,
            color:C.neon,letterSpacing:2,marginBottom:6}}>AI ZOMBIE PREDICTION ENGINE</div>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
            color:C.dim,lineHeight:1.7,letterSpacing:.3}}>
            GradientBoosting ML · 8 features: API usage patterns, ownership signals,
            lifecycle stage, security posture · 30/60/90-day forecasts
          </div>
        </div>
        <Btn variant="plasma" onClick={loadPreds} disabled={loading}>
          {loading?<><Spin/> Running ML...</>:"⬡ Run ML Predictions"}
        </Btn>
      </div>
      {preds.length>0&&(
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",
          gap:12,marginBottom:18}}>
          {[
            ["Total Analyzed",preds.length,C.neon],
            ["CRITICAL Risk",preds.filter(p=>p.risk_level==="CRITICAL").length,C.red],
            ["HIGH Risk",preds.filter(p=>p.risk_level==="HIGH").length,C.orange],
            ["LOW/SAFE",preds.filter(p=>p.risk_level==="LOW").length,C.green],
          ].map(([k,v,c])=>(
            <div key={k} style={{background:C.panel,border:`1px solid ${C.border}`,
              borderRadius:6,padding:"14px 16px",position:"relative",overflow:"hidden"}}>
              <div style={{position:"absolute",top:0,left:0,right:0,height:1,
                background:c,opacity:.6}}/>
              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:8}}>{k}</div>
              <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:30,
                fontWeight:900,color:c,textShadow:`0 0 20px ${c}55`}}>
                {String(v).padStart(2,"0")}
              </div>
            </div>
          ))}
        </div>
      )}
      <div style={{display:"grid",gridTemplateColumns:"1fr 320px",gap:16}}>
        <Panel title="ML Zombie Probability Rankings"
          icon="◈" meta={`${preds.length} APIs analyzed`} accent={C.plasma}>
          {loading?(
            <div style={{padding:40,textAlign:"center",color:C.dim,
              fontFamily:"'JetBrains Mono',monospace",fontSize:10}}>
              <Spin/> Running GradientBoosting predictions...
            </div>
          ):!preds.length?<Empty icon="◈" msg="Run a scan first."/>:(
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse"}}>
                <thead><tr>
                  {["API Path","Status","Risk Lvl","Now","30 Days","60 Days","90 Days",""].map(h=>(
                    <th key={h} style={{padding:"9px 12px",textAlign:"left",
                      fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                      letterSpacing:2,color:C.dim,borderBottom:`1px solid ${C.border}`,
                      background:"rgba(0,0,0,.3)",textTransform:"uppercase",
                      whiteSpace:"nowrap"}}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {preds.map((p,i)=>(
                    <tr key={i} onClick={()=>setSelPred(p)}
                      style={{cursor:"pointer",
                        background:selPred?.path===p.path?`${C.neon}06`:"transparent"}}>
                      <td style={{padding:"10px 12px",
                        fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                        color:p.zombie_probability>=75?C.red:
                          p.zombie_probability>=50?C.amber:C.text,
                        borderBottom:`1px solid ${C.border}40`,
                        maxWidth:200,overflow:"hidden",
                        textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.path}</td>
                      <td style={{padding:"10px 12px",borderBottom:`1px solid ${C.border}40`}}>
                        <Badge status={p.status||"active"}/>
                      </td>
                      <td style={{padding:"10px 12px",borderBottom:`1px solid ${C.border}40`}}>
                        <SevBadge sev={p.risk_level||"LOW"}/>
                      </td>
                      <td style={{padding:"10px 12px",borderBottom:`1px solid ${C.border}40`}}>
                        <div style={{fontFamily:"'JetBrains Mono',monospace",
                          fontSize:11,fontWeight:700,color:sevC(p.risk_level||"LOW")}}>
                          {p.zombie_probability}%
                        </div>
                      </td>
                      {[p.prediction_30d,p.prediction_60d,p.prediction_90d].map((v,j)=>(
                        <td key={j} style={{padding:"10px 12px",
                          fontFamily:"'JetBrains Mono',monospace",fontSize:10,
                          color:v>=75?C.red:v>=50?C.amber:C.dim,
                          borderBottom:`1px solid ${C.border}40`}}>{v}%</td>
                      ))}
                      <td style={{padding:"10px 12px",borderBottom:`1px solid ${C.border}40`}}>
                        <button onClick={e=>{e.stopPropagation();setSelPred(p);}}
                          style={{background:"transparent",border:`1px solid ${C.border}`,
                            borderRadius:3,padding:"3px 8px",cursor:"pointer",
                            fontFamily:"'JetBrains Mono',monospace",
                            fontSize:8,color:C.dim}}>→</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <div>
          {selPred?(
            <Panel title="Prediction Detail" icon="◈"
              meta={selPred.path} accent={sevC(selPred.risk_level||"LOW")}>
              <div style={{padding:16}}>
                <div style={{marginBottom:16}}>
                  <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:32,
                    fontWeight:900,color:sevC(selPred.risk_level||"LOW"),
                    textShadow:`0 0 20px ${sevC(selPred.risk_level||"LOW")}55`,
                    marginBottom:4}}>{selPred.zombie_probability}%</div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",
                    fontSize:8,color:C.dim}}>CURRENT ZOMBIE PROBABILITY</div>
                </div>
                <div style={{marginBottom:16}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                    color:C.dim,letterSpacing:2,marginBottom:10}}>
                    PROBABILITY FORECAST
                  </div>
                  <MLBar v={selPred.zombie_probability} label="NOW"/>
                  <div style={{height:8}}/>
                  <MLBar v={selPred.prediction_30d} label="30 DAYS"/>
                  <div style={{height:8}}/>
                  <MLBar v={selPred.prediction_60d} label="60 DAYS"/>
                  <div style={{height:8}}/>
                  <MLBar v={selPred.prediction_90d} label="90 DAYS"/>
                </div>
                <div style={{background:C.bg,border:`1px solid ${C.border}`,
                  borderRadius:4,padding:"10px 12px",marginBottom:12}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                    color:C.dim,letterSpacing:2,marginBottom:4}}>PREDICTED ZOMBIE DATE</div>
                  <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:13,
                    fontWeight:700,color:sevC(selPred.risk_level||"LOW")}}>
                    {selPred.predicted_zombie_date||"Unknown"}
                  </div>
                </div>
                <div style={{background:C.bg,border:`1px solid ${C.border}`,
                  borderRadius:4,padding:"10px 12px",marginBottom:12}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                    color:C.dim,letterSpacing:2,marginBottom:4}}>MODEL CONFIDENCE</div>
                  <MLBar v={selPred.confidence||75}/>
                </div>
                <div style={{
                  background:`${sevC(selPred.risk_level||"LOW")}08`,
                  border:`1px solid ${sevC(selPred.risk_level||"LOW")}33`,
                  borderRadius:4,padding:"10px 12px",
                  fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                  color:sevC(selPred.risk_level||"LOW"),lineHeight:1.6,letterSpacing:.3}}>
                  {selPred.recommendation||"Continue standard monitoring."}
                </div>
              </div>
            </Panel>
          ):(
            <Panel title="Prediction Detail" icon="◈" accent={C.plasma}>
              <Empty icon="◈" msg="Click any row to see detailed ML prediction"/>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
function PageArchitecture({apis}){
  const[stats,setStats]=useState(null);
  useEffect(()=>{
    fetch(`${API}/stats`).then(r=>r.ok?r.json():null)
      .then(d=>setStats(d)).catch(()=>{});
  },[]);
  const flow=[
    {id:"scanner",label:"API Scanner",icon:"⬡",
     desc:"Scans network. Finds undocumented APIs. Real URL probing.",
     color:C.neon,stat:`${apis.length} APIs found`},
    {id:"registry",label:"API Registry",icon:"▤",
     desc:"Persistent TinyDB store. Tracks every discovered endpoint.",
     color:C.neon2,stat:`${stats?.registry_total||apis.length} registered`},
    {id:"analyzer",label:"Security Analyzer",icon:"◈",
     desc:"Checks API exposure. Analyzes auth and encryption gaps.",
     color:C.amber,stat:`Avg risk: ${
       apis.length?Math.round(apis.reduce((s,a)=>s+a.risk,0)/apis.length):0}/100`},
    {id:"zombie",label:"Zombie Detection",icon:"☠",
     desc:"Identifies dormant APIs. Uses behavioral ML logic.",
     color:C.red,stat:`${apis.filter(a=>a.status==="zombie").length} detected`},
    {id:"ai",label:"AI Prediction",icon:"🤖",
     desc:"GradientBoosting ML. 30/60/90-day zombie forecasts.",
     color:C.plasma,stat:`${
       apis.filter(a=>(a.ml_zombie_probability||0)>=50).length} at-risk`},
    {id:"defense",label:"Defense Engine",icon:"🍯",
     desc:"Honeypot + quarantine + auto-defend. Zero intervention.",
     color:C.green,stat:`${apis.filter(a=>a.honeypot).length} active`},
  ];
  return(
    <div>
      <Panel title="System Architecture — Scan → Registry → Analyze → Detect → Predict → Defend"
        icon="⬡" accent={C.neon}>
        <div style={{padding:"20px 20px 8px"}}>
          <div style={{display:"flex",alignItems:"stretch",gap:0,marginBottom:20}}>
            {flow.map((step,i)=>(
              <div key={step.id} style={{display:"flex",alignItems:"center",flex:1}}>
                <div style={{flex:1,background:C.bg3,
                  border:`1px solid ${step.color}44`,borderRadius:6,
                  padding:"14px 12px",position:"relative",
                  overflow:"hidden",textAlign:"center"}}>
                  <div style={{position:"absolute",top:0,left:0,right:0,
                    height:2,background:step.color,opacity:.6}}/>
                  <div style={{fontSize:20,marginBottom:6}}>{step.icon}</div>
                  <div style={{fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
                    fontSize:11,color:step.color,letterSpacing:1,
                    marginBottom:6,textTransform:"uppercase"}}>{step.label}</div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                    color:C.dim,lineHeight:1.5,marginBottom:8}}>{step.desc}</div>
                  <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:11,
                    fontWeight:700,color:step.color}}>{step.stat}</div>
                </div>
                {i<flow.length-1&&(
                  <div style={{padding:"0 5px",flexShrink:0,
                    display:"flex",flexDirection:"column",
                    alignItems:"center",gap:2}}>
                    <div style={{width:18,height:1,background:C.border}}/>
                    <div style={{fontFamily:"'JetBrains Mono',monospace",
                      fontSize:12,color:C.border}}>›</div>
                    <div style={{width:18,height:1,background:C.border}}/>
                  </div>
                )}
              </div>
            ))}
          </div>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
            color:C.dim,letterSpacing:2,marginBottom:12,textTransform:"uppercase"}}>
            TECHNOLOGY STACK
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:8,marginBottom:20}}>
            {[
              {layer:"LAYER 1",tech:"Python + React",color:C.neon},
              {layer:"LAYER 2",tech:"FastAPI + Uvicorn",color:C.neon},
              {layer:"LAYER 3",tech:"React + Vite",color:C.green},
              {layer:"LAYER 4",tech:"D3.js / SVG",color:C.amber},
              {layer:"LAYER 5",tech:"scikit-learn ML",color:C.orange},
              {layer:"LAYER 6",tech:"TinyDB Registry",color:C.red},
            ].map((t,i)=>(
              <div key={i} style={{background:C.bg,border:`1px solid ${C.border}`,
                borderRadius:4,padding:"8px 10px",borderLeft:`2px solid ${t.color}`}}>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                  color:C.dim,letterSpacing:1,marginBottom:4}}>{t.layer}</div>
                <div style={{fontFamily:"'Rajdhani',sans-serif",fontWeight:600,
                  fontSize:11,color:t.color}}>{t.tech}</div>
              </div>
            ))}
          </div>
        </div>
      </Panel>
      <Panel title="Impact: Before vs After NECROS X" icon="◈" accent={C.green}>
        <div style={{padding:"16px 20px"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
            <div style={{background:`${C.red}06`,border:`1px solid ${C.red}30`,
              borderRadius:6,padding:"16px 18px"}}>
              <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:12,
                fontWeight:700,color:C.red,letterSpacing:2,marginBottom:14}}>
                WITHOUT NECROS X
              </div>
              {[
                ["Detection Time","212 days avg",C.red],
                ["False Positives","67% noise",C.red],
                ["Response","Manual process",C.red],
                ["Zombie APIs","Undetected",C.red],
                ["Future Prediction","Not possible",C.red],
                ["Defense","Days to weeks",C.red],
              ].map(([k,v,c])=>(
                <div key={k} style={{display:"flex",justifyContent:"space-between",
                  marginBottom:8,fontFamily:"'JetBrains Mono',monospace",fontSize:9}}>
                  <span style={{color:C.dim}}>▸ {k}</span>
                  <span style={{color:c,fontWeight:700}}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{background:`${C.green}06`,border:`1px solid ${C.green}30`,
              borderRadius:6,padding:"16px 18px"}}>
              <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:12,
                fontWeight:700,color:C.green,letterSpacing:2,marginBottom:14}}>
                WITH NECROS X
              </div>
              {[
                ["Detection Time","< 30 seconds",C.green],
                ["False Positives","ML-filtered",C.green],
                ["Response","Automated",C.green],
                ["Zombie APIs","Detected + Trapped",C.green],
                ["Future Prediction","90-day ML forecast",C.green],
                ["Defense","1 click / auto",C.green],
              ].map(([k,v,c])=>(
                <div key={k} style={{display:"flex",justifyContent:"space-between",
                  marginBottom:8,fontFamily:"'JetBrains Mono',monospace",fontSize:9}}>
                  <span style={{color:C.dim}}>✓ {k}</span>
                  <span style={{color:c,fontWeight:700}}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function PageDashboard({apis,sum,scanning,prog,target,setTarget,onScan,alerts,onAck,demoStep}){
  const tl=sum?.tl||"NONE";
  const tlC={CRITICAL:C.red,HIGH:C.orange,MEDIUM:C.amber,NONE:C.green}[tl]||C.green;
  const zombies=apis.filter(a=>a.status==="zombie");
  const openA=alerts.filter(a=>!a.ack);
  const mlAtRisk=apis.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active");
  return(
    <div>
      <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:6,
        padding:"12px 18px",marginBottom:18,display:"flex",gap:12,alignItems:"center",
        position:"relative",overflow:"hidden"}}>
        <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:C.dim,
          position:"absolute",top:6,left:18,letterSpacing:2,pointerEvents:"none"}}>
          TARGET //
        </span>
        <input value={target} onChange={e=>setTarget(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&onScan()}
          style={{flex:1,background:"transparent",border:"none",outline:"none",marginTop:10,
            fontFamily:"'JetBrains Mono',monospace",fontSize:12,color:C.neon,
            letterSpacing:1,caretColor:C.neon}}
          placeholder="https://api.target.com"/>
        <div style={{width:1,height:28,background:C.border,flexShrink:0}}/>
        <button onClick={onScan} disabled={scanning}
          style={{padding:"10px 26px",borderRadius:4,border:`1px solid ${C.neon}`,
            cursor:scanning?"not-allowed":"pointer",
            fontFamily:"'Rajdhani',sans-serif",fontWeight:700,fontSize:13,letterSpacing:2,
            background:scanning?"transparent":C.neon,
            color:scanning?C.neon:C.bg,
            boxShadow:scanning?"none":`0 0 24px ${C.neon}55`,
            opacity:scanning?.6:1,transition:"all .2s"}}>
          {scanning?"◌  SCANNING…":"⬡  INITIATE SCAN"}
        </button>
      </div>
      {scanning&&(
        <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:6,
          padding:"16px 20px",marginBottom:18,
          display:"grid",gridTemplateColumns:"1fr 90px",gap:16,alignItems:"start"}}>
          <div>
            <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
              color:C.neon,letterSpacing:2,marginBottom:8}}>◈ SCANNING — {target}</div>
            <div style={{height:2,background:C.bg,borderRadius:1,
              overflow:"hidden",marginBottom:12}}>
              <div style={{height:"100%",width:`${prog}%`,transition:"width .4s",borderRadius:1,
                background:`linear-gradient(90deg,${C.neon2},${C.neon})`,
                boxShadow:`0 0 8px ${C.neon}`}}/>
            </div>
            {["DNS Resolution & Port Discovery","API Endpoint Enumeration",
              "Authentication Layer Analysis","Encryption & TLS Audit",
              "Zombie Classification Engine","ML Prediction Engine (GradientBoosting)",
            ].map((s,i)=>{
              const done=prog>i*16+10,act=prog>i*16&&!done;
              return(
                <div key={s} style={{display:"flex",alignItems:"center",gap:7,marginBottom:3,
                  fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                  color:done?C.green:act?C.neon:C.dim}}>
                  <div style={{width:4,height:4,borderRadius:"50%",
                    background:"currentColor",flexShrink:0}}/>
                  {s}{done&&<span style={{color:C.green,marginLeft:"auto"}}>✓</span>}
                </div>
              );
            })}
          </div>
          <div>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:38,fontWeight:900,
              color:C.neon,textAlign:"right",lineHeight:1,
              textShadow:`0 0 20px ${C.neon}88`}}>{prog}%</div>
            <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:C.dim,
              textAlign:"right",marginTop:5,letterSpacing:1}}>COMPLETE</div>
          </div>
        </div>
      )}
      {sum&&(
        <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:12,marginBottom:18}}>
          {[
            {lbl:"APIs Found",val:sum.total,acc:C.neon,sub:"Surface mapped"},
            {lbl:"Zombie APIs",val:sum.zombie,acc:C.red,sub:"Critical — act now"},
            {lbl:"Deprecated",val:sum.dep,acc:C.orange,sub:"Legacy exposure"},
            {lbl:"Avg Risk",val:sum.avg,acc:tlC,sub:`Threat: ${tl}`},
            {lbl:"ML At-Risk",val:mlAtRisk.length,acc:C.amber,sub:"AI predicts zombie"},
          ].map(k=>(
            <div key={k.lbl} style={{background:C.panel,border:`1px solid ${C.border}`,
              borderRadius:6,padding:"16px 18px",position:"relative",overflow:"hidden"}}>
              <div style={{position:"absolute",top:0,left:0,right:0,
                height:1,background:k.acc,opacity:.65}}/>
              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:10}}>{k.lbl}</div>
              <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:34,fontWeight:900,
                color:k.acc,lineHeight:1,textShadow:`0 0 24px ${k.acc}66`}}>
                {String(k.val).padStart(2,"0")}
              </div>
              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                color:C.dim,marginTop:8}}>{k.sub}</div>
            </div>
          ))}
        </div>
      )}
      {sum&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:18}}>
          <Panel title="Risk Distribution" icon="◈" accent={C.neon}>
            <RiskChart apis={apis}/>
          </Panel>
          <Panel title="Alert Center" icon="🔔"
            meta={`${openA.length} open`}
            accent={openA.length>0?C.red:C.green}>
            <AlertCenter alerts={alerts} onAck={onAck}/>
          </Panel>
        </div>
      )}
      {mlAtRisk.length>0&&(
        <div style={{background:`${C.amber}0a`,border:`1px solid ${C.amber}40`,
          borderRadius:6,padding:"14px 18px",marginBottom:18,
          position:"relative",overflow:"hidden"}}>
          <div style={{position:"absolute",top:0,left:0,right:0,height:1,
            background:`linear-gradient(90deg,${C.amber},transparent)`}}/>
          <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
            <span style={{fontSize:16}}>🤖</span>
            <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:11,fontWeight:700,
              color:C.amber,letterSpacing:2}}>AI ZOMBIE PREDICTION ALERT</span>
            <span style={{marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",
              fontSize:9,color:C.amber,background:`${C.amber}18`,
              border:`1px solid ${C.amber}44`,padding:"2px 9px",borderRadius:3}}>
              {mlAtRisk.length} AT RISK
            </span>
          </div>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
            color:C.dim,marginBottom:10,letterSpacing:.3}}>
            ML model predicts these ACTIVE APIs will become zombie threats within 90 days:
          </div>
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            {mlAtRisk.map(a=>(
              <div key={a.id} style={{background:`${C.amber}0d`,
                border:`1px solid ${C.amber}30`,borderRadius:4,padding:"9px 14px"}}>
                <div style={{fontFamily:"'JetBrains Mono',monospace",
                  fontSize:10,color:C.amber,marginBottom:4}}>{a.path}</div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:C.dim}}>
                  ML:{(a.ml_zombie_probability||0).toFixed(0)}% | 90d:{a.ml_prediction_90d||0}% | {a.ml_risk_level}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
{zombies.length>0&&(
        <div style={{background:`${C.red}0a`,border:`1px solid ${C.red}40`,
          borderRadius:6,padding:"14px 18px",marginBottom:18,
          position:"relative",overflow:"hidden"}}>
          <div style={{position:"absolute",top:0,left:0,right:0,height:1,
            background:`linear-gradient(90deg,${C.red},transparent)`}}/>
          <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
            <span style={{fontSize:16}}>☠</span>
            <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:11,fontWeight:700,
              color:C.red,letterSpacing:2}}>ZOMBIE API DETECTION ALERT</span>
            <span style={{marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",
              fontSize:9,color:C.red,background:`${C.red}18`,
              border:`1px solid ${C.red}44`,padding:"2px 9px",borderRadius:3,
              animation:"badgePulse 1.5s infinite"}}>
              {zombies.length} CRITICAL
            </span>
          </div>
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            {zombies.map(a=>(
              <div key={a.id} style={{background:`${C.red}0d`,
                border:`1px solid ${C.red}30`,borderRadius:4,padding:"9px 14px"}}>
                <div style={{fontFamily:"'JetBrains Mono',monospace",
                  fontSize:10,color:C.red,marginBottom:4}}>{a.path}</div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:C.dim}}>
                  RISK:{a.risk} · ML:{(a.ml_zombie_probability||0).toFixed(0)}% · {a.seen}
                </div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                  color:C.muted,marginTop:3,fontStyle:"italic"}}>{a.desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {apis.length>0&&(
        <Panel title="API Surface Map" icon="≡"
          meta={`${apis.length} endpoints`} badge={`SCAN-${uid()}`}>
          <div style={{overflowX:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr>
                {["Path","Owner","Layer","Methods","Status","Risk","Auth","TLS","ML%","Calls/Day","Last Active"].map(h=>(
                  <th key={h} style={{padding:"9px 12px",textAlign:"left",
                    fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                    letterSpacing:2,color:C.dim,borderBottom:`1px solid ${C.border}`,
                    background:"rgba(0,0,0,.3)",textTransform:"uppercase",
                    whiteSpace:"nowrap"}}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {apis.map(a=>(
                  <tr key={a.id} style={{
                    background:a.status==="zombie"?`${C.red}05`:
                      a.honeypot?`${C.neon}04`:
                      (a.ml_zombie_probability||0)>=50?`${C.amber}03`:"transparent"}}>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:9,letterSpacing:.3,
                      color:a.status==="zombie"?C.red:a.honeypot?C.neon:
                        (a.ml_zombie_probability||0)>=50?C.amber:C.text,
                      borderBottom:`1px solid ${C.border}40`,
                      maxWidth:180,overflow:"hidden",
                      textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.path}</td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:8,color:C.dim,borderBottom:`1px solid ${C.border}40`,
                      maxWidth:100,overflow:"hidden",textOverflow:"ellipsis",
                      whiteSpace:"nowrap"}}>{a.owner||"unknown"}</td>
                    <td style={{padding:"9px 12px",borderBottom:`1px solid ${C.border}40`}}>
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                        padding:"2px 6px",borderRadius:3,
                        background:"rgba(255,255,255,.04)",color:C.dim,
                        border:`1px solid ${C.border}`}}>{a.layer}</span>
                    </td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:8,color:C.dim,borderBottom:`1px solid ${C.border}40`}}>
                      {(a.methods||["GET"]).join("·")}
                    </td>
                    <td style={{padding:"9px 12px",borderBottom:`1px solid ${C.border}40`}}>
                      <Badge status={a.status}/>
                    </td>
                    <td style={{padding:"9px 12px",borderBottom:`1px solid ${C.border}40`}}>
                      <RiskBar v={a.risk||a.risk_score||0}/>
                    </td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:10,color:a.auth?C.green:C.red,
                      borderBottom:`1px solid ${C.border}40`}}>
                      {a.auth?"✓":"✗"}
                    </td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:10,color:a.enc?C.green:C.red,
                      borderBottom:`1px solid ${C.border}40`}}>
                      {a.enc?"✓":"✗"}
                    </td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:10,fontWeight:700,
                      color:(a.ml_zombie_probability||0)>=75?C.red:
                        (a.ml_zombie_probability||0)>=50?C.amber:C.dim,
                      borderBottom:`1px solid ${C.border}40`}}>
                      {(a.ml_zombie_probability||0).toFixed(0)}%
                    </td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:9,color:C.neon2,borderBottom:`1px solid ${C.border}40`}}>
                      {(a.calls_per_day||0).toLocaleString()}
                    </td>
                    <td style={{padding:"9px 12px",fontFamily:"'JetBrains Mono',monospace",
                      fontSize:9,color:C.muted,borderBottom:`1px solid ${C.border}40`}}>
                      {a.seen}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
      {!apis.length&&!scanning&&(
        <Empty icon="⬡" msg="Enter a target URL above and click INITIATE SCAN"/>
      )}
    </div>
  );
}

function PageDetails({apis,setApis,atkLogs,setAtkLogs,hpLogs,setHpLogs,demoStep,setDemoStep,alerts,setAlerts}){
  const[sel,setSel]=useState(null);
  const[atkR,setAtkR]=useState(null);
  const[defR,setDefR]=useState(null);
  const[aBusy,setABusy]=useState(false);
  const[dBusy,setDBusy]=useState(false);
  const[adBusy,setAdBusy]=useState(false);
  useEffect(()=>{
    if(sel){const u=apis.find(a=>a.id===sel.id);if(u)setSel(u);}
  },[apis]);
  const doAtk=useCallback(async()=>{
    if(!sel||aBusy)return;
    setABusy(true);setAtkR(null);
    await new Promise(r=>setTimeout(r,1100));
    const atk=MOCK_ATKS[rnd(0,MOCK_ATKS.length-1)];
    let outcome="BLOCKED",detail="WAF + rate-limit triggered.";
    if(sel.honeypot){outcome="TRAPPED";detail="Attacker diverted. Fingerprint captured.";}
    else if(!sel.auth){
      outcome="BREACH";detail="No auth. Full unauthorized access.";
      voiceAlert("Warning. Breach detected. Immediate action required.");
    }else if(sel.status==="zombie"&&!sel.enc){
      outcome="BREACH";detail="Deprecated token exploited. Data exposed.";
      voiceAlert("Warning. Breach detected.");
    }
    const log={id:uid(),ts:ts(),ip:rndIP(),path:sel.path,
      type:atk.type,vec:atk.vec,sev:atk.sev,
      owasp:atk.owasp,cve:atk.cve,outcome,detail};
    setAtkLogs(l=>[...l,log]);setAtkR(log);
    if(outcome==="BREACH"){
      setAlerts(a=>[...a,{id:uid(),type:"BREACH_DETECTED",sev:"CRITICAL",
        path:sel.path,msg:`ACTIVE BREACH: ${sel.path} via ${atk.type}`,ts:ts(),ack:false}]);
    }
    if(demoStep===2)setDemoStep(3);
    setABusy(false);
  },[sel,aBusy,demoStep]);
  const doDef=useCallback(async()=>{
    if(!sel||dBusy||sel.status==="active"||sel.honeypot)return;
    setDBusy(true);setDefR(null);
    await new Promise(r=>setTimeout(r,900));
    setApis(prev=>prev.map(a=>a.id===sel.id
      ?{...a,honeypot:true,status:"honeypot",risk:Math.max(a.risk-40,5)}:a));
    const traps=Array.from({length:rnd(2,5)},()=>({
      ip:rndIP(),action:MOCK_ACTIONS[rnd(0,MOCK_ACTIONS.length-1)],
      data:MOCK_INTEL[rnd(0,MOCK_INTEL.length-1)],
      dwell:rnd(4,62),ts:ts(),
    }));
    setHpLogs(l=>[...l,...traps]);
    setDefR({path:sel.path,traps});
    setAlerts(a=>[...a,{id:uid(),type:"HONEYPOT_ACTIVE",sev:"INFO",
      path:sel.path,msg:`Honeypot live: ${sel.path} — ${traps.length} trapped`,
      ts:ts(),ack:false}]);
    if(demoStep===3)setDemoStep(4);
    setDBusy(false);
  },[sel,dBusy,demoStep,apis]);
  const doAutoDefend=useCallback(async()=>{
    setAdBusy(true);
    await new Promise(r=>setTimeout(r,800));
    let count=0;
    setApis(prev=>prev.map(a=>{
      if(a.status==="zombie"&&!a.honeypot){
        count++;
        const traps=Array.from({length:rnd(1,3)},()=>({
          ip:rndIP(),action:MOCK_ACTIONS[rnd(0,MOCK_ACTIONS.length-1)],
          data:MOCK_INTEL[rnd(0,MOCK_INTEL.length-1)],
          dwell:rnd(4,30),ts:ts(),
        }));
        setHpLogs(l=>[...l,...traps]);
        return{...a,honeypot:true,status:"honeypot",risk:Math.max(a.risk-40,5)};
      }
      return a;
    }));
    if(count>0){
      setAlerts(a=>[...a,{id:uid(),type:"AUTO_DEFEND_COMPLETE",sev:"INFO",
        path:"ALL ZOMBIES",
        msg:`Auto-defense: ${count} honeypots deployed (zero manual intervention)`,
        ts:ts(),ack:false}]);
      voiceAlert(`Auto defense activated. ${count} honeypots deployed.`);
    }
    setAdBusy(false);
  },[apis]);
  const sevC=s=>s==="CRITICAL"?C.red:s==="HIGH"?C.orange:C.amber;
  return(
    <div>
      <DemoBanner step={demoStep}/>
      <div style={{background:C.panel,border:`1px solid ${C.border}`,borderRadius:6,
        padding:"12px 18px",marginBottom:16,display:"flex",alignItems:"center",gap:16}}>
        <div style={{flex:1}}>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:11,fontWeight:700,
            color:C.neon,letterSpacing:2,marginBottom:4}}>ZERO MANUAL INTERVENTION MODE</div>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:C.dim}}>
            Auto-deploy honeypots on ALL zombie APIs simultaneously. No manual selection required.
          </div>
        </div>
        <Btn variant="warning" onClick={doAutoDefend}
          disabled={adBusy||!apis.some(a=>a.status==="zombie"&&!a.honeypot)}>
          {adBusy?<><Spin/> Defending...</>:"⚡ AUTO-DEFEND ALL ZOMBIES"}
        </Btn>
      </div>
<div style={{display:"grid",gridTemplateColumns:"290px 1fr",gap:16,marginBottom:18}}>
        <Panel title="Select Endpoint" icon="◎" meta={`${apis.length} found`}>
          <div style={{maxHeight:420,overflowY:"auto"}}>
            {!apis.length&&<Empty icon="◎" msg="Run a scan first."/>}
            {apis.map(a=>(
              <div key={a.id} onClick={()=>{setSel(a);setAtkR(null);setDefR(null);
                if(demoStep===1)setDemoStep(2);}}
                style={{padding:"10px 20px",cursor:"pointer",display:"flex",
                  alignItems:"center",gap:10,borderBottom:`1px solid ${C.border}`,
                  transition:"background .15s",
                  background:sel?.id===a.id?`${C.neon}08`:"transparent",
                  borderLeft:sel?.id===a.id?`2px solid ${C.neon}`:"2px solid transparent"}}>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                    letterSpacing:.3,marginBottom:2,overflow:"hidden",
                    textOverflow:"ellipsis",whiteSpace:"nowrap",
                    color:a.status==="zombie"?C.red:a.honeypot?C.neon:
                      (a.ml_zombie_probability||0)>=50?C.amber:C.text}}>
                    {a.honeypot?"🍯 ":a.status==="zombie"?"☠ ":
                     (a.ml_zombie_probability||0)>=50?"⚠ ":""}{a.path}
                  </div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                    color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                    {a.desc}
                  </div>
                </div>
                <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",
                  gap:3,flexShrink:0}}>
                  <Badge status={a.status}/>
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                    fontWeight:700,color:a.risk>=70?C.red:a.risk>=45?C.orange:C.green}}>
                    {a.risk}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
        {sel?(
          <Panel title="Endpoint Analysis"
            icon={sel.honeypot?"🍯":sel.status==="zombie"?"☠":"◈"}
            meta={sel.path} accent={sColor(sel.status)}>
            <div style={{padding:18}}>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",
                gap:10,marginBottom:14}}>
                {[
                  {k:"Status",v:<Badge status={sel.status}/>,acc:sColor(sel.status)},
                  {k:"Risk Score",v:(
                    <div style={{display:"flex",alignItems:"baseline",gap:4}}>
                      <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:24,
                        fontWeight:900,color:sel.risk>=70?C.red:sel.risk>=45?C.orange:C.green}}>
                        {sel.risk}
                      </span>
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.dim}}>/100</span>
                    </div>
                  ),acc:sel.risk>=70?C.red:sel.risk>=45?C.orange:C.green},
                  {k:"ML Zombie Risk",v:(
                    <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:20,fontWeight:900,
                      color:(sel.ml_zombie_probability||0)>=75?C.red:
                        (sel.ml_zombie_probability||0)>=50?C.amber:C.green}}>
                      {(sel.ml_zombie_probability||0).toFixed(1)}%
                    </div>
                  ),acc:(sel.ml_zombie_probability||0)>=75?C.red:
                    (sel.ml_zombie_probability||0)>=50?C.amber:C.green},
                  {k:"Authentication",v:(
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,
                      color:sel.auth?C.green:C.red}}>
                      {sel.auth?"✓ ENABLED":"✗ MISSING"}
                    </span>
                  ),acc:sel.auth?C.green:C.red},
                  {k:"TLS Encryption",v:(
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,
                      color:sel.enc?C.green:C.red}}>
                      {sel.enc?"✓ ACTIVE":"✗ PLAINTEXT"}
                    </span>
                  ),acc:sel.enc?C.green:C.red},
                  {k:"Owner",v:(
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.neon2}}>
                      {sel.owner||"unknown"}
                    </span>
                  ),acc:C.neon2},
                ].map(d=>(
                  <div key={d.k} style={{background:C.bg2,border:`1px solid ${C.border}`,
                    borderRadius:4,padding:"11px 13px",borderTop:`1px solid ${d.acc}55`}}>
                    <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                      color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:7}}>
                      {d.k}
                    </div>
                    {d.v}
                  </div>
                ))}
              </div>
              <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:4,
                padding:"11px 14px",marginBottom:14}}>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                  color:C.dim,marginBottom:8,letterSpacing:2}}>ML ZOMBIE FORECAST</div>
                {[["NOW",sel.ml_zombie_probability||0],["30d",sel.ml_prediction_30d||0],
                  ["60d",sel.ml_prediction_60d||0],["90d",sel.ml_prediction_90d||0],
                ].map(([lbl,v])=>(
                  <div key={lbl} style={{display:"flex",alignItems:"center",gap:10,marginBottom:7}}>
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                      color:C.dim,minWidth:28,letterSpacing:1}}>{lbl}</span>
                    <div style={{flex:1,height:5,background:C.bg,borderRadius:3,overflow:"hidden"}}>
                      <div style={{width:`${v}%`,height:"100%",
                        background:v>=75?C.red:v>=50?C.amber:C.green,
                        boxShadow:`0 0 5px ${v>=75?C.red:v>=50?C.amber:C.green}`,
                        borderRadius:3,transition:"width .8s"}}/>
                    </div>
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,
                      fontWeight:700,minWidth:36,
                      color:v>=75?C.red:v>=50?C.amber:C.green,textAlign:"right"}}>
                      {v.toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
              <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:4,
                padding:"11px 14px",marginBottom:14,
                fontFamily:"'JetBrains Mono',monospace",fontSize:8}}>
                <div style={{color:C.dim,marginBottom:8,letterSpacing:2}}>RISK FACTOR BREAKDOWN</div>
                {[
                  {lbl:"No Authentication",pts:35,on:!sel.auth,owasp:"API2"},
                  {lbl:"No TLS Encryption",pts:25,on:!sel.enc,owasp:"API8"},
                  {lbl:"Inactivity > 180 days",pts:30,on:sel.days>180,owasp:"API9"},
                  {lbl:"Inactivity 60–180 days",pts:15,on:sel.days>60&&sel.days<=180,owasp:"API9"},
                  {lbl:"Zombie classification",pts:10,on:sel.status==="zombie",owasp:"API9"},
                ].map(f=>(
                  <div key={f.lbl} style={{display:"flex",alignItems:"center",
                    gap:8,marginBottom:5,opacity:f.on?1:.22}}>
                    <span style={{color:f.on?C.red:C.dim,minWidth:8}}>{f.on?"▸":"○"}</span>
                    <span style={{flex:1,color:f.on?C.text:C.dim}}>{f.lbl}</span>
                    {f.on&&<span style={{fontSize:7,color:C.neon2,background:`${C.neon}10`,
                      padding:"1px 5px",borderRadius:2,border:`1px solid ${C.neon}28`,
                      marginRight:4}}>{f.owasp}</span>}
                    <span style={{color:f.on?C.red:C.dim,fontWeight:700,
                      minWidth:30,textAlign:"right"}}>+{f.pts}</span>
                  </div>
                ))}
              </div>
              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,color:C.dim,
                letterSpacing:.3,marginBottom:14,padding:"8px 12px",background:C.bg,
                border:`1px solid ${C.border}`,borderRadius:4,fontStyle:"italic"}}>
                {sel.desc}
              </div>
              <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                <Btn variant="danger" onClick={doAtk} disabled={aBusy}>
                  {aBusy?<><Spin/> Executing…</>:"⚡ Simulate Attack"}
                </Btn>
                {!sel.honeypot&&sel.status!=="active"&&(
                  <Btn variant="success" onClick={doDef} disabled={dBusy}>
                    {dBusy?<><Spin/> Deploying…</>:"🍯 Deploy Honeypot"}
                  </Btn>
                )}
                {sel.status==="active"&&!sel.honeypot&&(
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                    color:C.dim,alignSelf:"center"}}>Active endpoints cannot be converted</span>
                )}
                {sel.honeypot&&(
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                    color:C.neon,alignSelf:"center"}}>🍯 Honeypot active — capturing traffic</span>
                )}
              </div>
            </div>
          </Panel>
        ):(
          <Panel title="Endpoint Analysis" icon="◈">
            <Empty icon="◎" msg="Select an endpoint to begin analysis"/>
          </Panel>
        )}
      </div>
      {atkR&&(
        <Panel title="Attack Simulation Report" icon="⚡"
          meta={`LOG #${atkR.id}`} badge={atkR.sev}
          accent={atkR.outcome==="BREACH"?C.red:atkR.outcome==="TRAPPED"?C.neon:C.green}>
          <div style={{padding:18}}>
            <div style={{display:"grid",gridTemplateColumns:"90px 1fr",background:C.bg,
              border:`1px solid ${C.border}`,borderRadius:4,overflow:"hidden",marginBottom:12}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"center",padding:16,
                borderRight:`1px solid ${C.border}`,
                background:atkR.outcome==="BREACH"?`${C.red}18`:
                  atkR.outcome==="TRAPPED"?`${C.neon}10`:`${C.green}0a`}}>
                <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:9,fontWeight:900,
                  letterSpacing:2,writingMode:"vertical-rl",textOrientation:"mixed",
                  color:atkR.outcome==="BREACH"?C.red:atkR.outcome==="TRAPPED"?C.neon:C.green}}>
                  {atkR.outcome}
                </span>
              </div>
              <div style={{padding:"13px 16px",fontFamily:"'JetBrains Mono',monospace",fontSize:9}}>
                {[["TIMESTAMP",atkR.ts,C.text],["ATTACKER IP",atkR.ip,C.red],
                  ["TARGET",atkR.path,C.text],["ATTACK TYPE",atkR.type,C.orange],
                  ["OWASP REF",atkR.owasp,C.neon2],["CVE",atkR.cve,C.muted],
                  ["VECTOR",atkR.vec,C.muted],["DETAIL",atkR.detail,C.text],
                ].map(([k,v,c])=>(
                  <div key={k} style={{display:"flex",gap:12,marginBottom:4}}>
                    <span style={{color:C.neon2,minWidth:112,letterSpacing:.3}}>{k}</span>
                    <span style={{color:c}}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
            {atkR.outcome==="BREACH"&&!sel?.honeypot&&(
              <div style={{padding:"10px 14px",background:`${C.red}0a`,
                border:`1px solid ${C.red}33`,borderRadius:4,
                fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                color:C.red,letterSpacing:.3}}>
                ⚠ BREACH CONFIRMED — Deploy honeypot before disabling to capture attacker IOCs.
              </div>
            )}
          </div>
        </Panel>
      )}
      {defR&&(
        <Panel title="Honeypot Deployment Report" icon="🍯"
          meta="INTEL VALUE: HIGH" accent={C.green}>
          <div style={{padding:18}}>
            <div style={{background:`${C.neon}09`,border:`1px solid ${C.neon}2a`,
              borderRadius:4,padding:"9px 14px",marginBottom:14,
              fontFamily:"'JetBrains Mono',monospace",fontSize:9,color:C.neon,letterSpacing:.3}}>
              ◈ '{defR.path}' converted to honeypot. All attacker traffic captured.
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:14}}>
              {[["Trapped",defR.traps.length,C.green],["Intel","HIGH",C.neon],
                ["Dwell",`${Math.min(...defR.traps.map(t=>t.dwell))}–${Math.max(...defR.traps.map(t=>t.dwell))}min`,C.amber],
                ["Status","ACTIVE",C.red],
              ].map(([k,v,c])=>(
                <div key={k} style={{background:C.bg,border:`1px solid ${C.border}`,
                  borderRadius:4,padding:"10px 13px",borderTop:`1px solid ${c}55`}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                    color:C.dim,letterSpacing:2,marginBottom:6}}>{k}</div>
                  <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:18,
                    fontWeight:900,color:c}}>{v}</div>
                </div>
              ))}
            </div>
            {defR.traps.map((t,i)=>(
              <div key={i} style={{background:`${C.neon}06`,border:`1px solid ${C.neon}1a`,
                borderRadius:4,padding:"10px 14px",marginBottom:8}}>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                  color:C.neon,letterSpacing:2,marginBottom:8}}>
                  ◈ ATTACKER #{String(i+1).padStart(2,"0")} TRAPPED
                  <span style={{color:C.dim,fontSize:7,marginLeft:8}}>(dwell:{t.dwell}min)</span>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                  {[["ATTACKER IP",t.ip,C.red],["ACTION",t.action,C.orange],
                    ["STATUS","Trapped in honeypot",C.green],["INTEL",t.data,C.neon],
                  ].map(([k,v,c])=>(
                    <div key={k}>
                      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                        color:C.dim,letterSpacing:1,marginBottom:2}}>{k}</div>
                      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                        color:c,wordBreak:"break-all"}}>{v}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
function PageGraph({apis}){
  const[picked,setPicked]=useState(null);
  const[showAtkPaths,setShowAtkPaths]=useState(false);
  const[atkPaths,setAtkPaths]=useState([]);
  const pickedApi=picked?apis.find(a=>a.id===picked):null;
  const loadAtkPaths=useCallback(async()=>{
    setShowAtkPaths(true);
    try{
      const r=await fetch(`${API}/attack/paths`);
      if(r.ok){const d=await r.json();setAtkPaths(d.attack_paths||[]);}
      else throw new Error();
    }catch{
      const zombies=apis.filter(a=>a.status==="zombie");
      const paths=zombies.map(z=>{
        const chain=[z.path];
        z.conns.forEach(id=>{
          const a=apis.find(x=>x.id===id);
          if(a)chain.push(a.path);
        });
        return{entry_point:z.path,risk:z.risk,attack_chain:chain,depth:chain.length,
          financial_reach:chain.some(p=>p.includes("payment"))};
      });
      setAtkPaths(paths);
    }
  },[apis]);
  return(
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:12,marginBottom:16}}>
        {[["Nodes",apis.length,C.neon],["Edges",apis.reduce((s,a)=>s+a.conns.length,0),C.neon],
          ["Zombies",apis.filter(a=>a.status==="zombie").length,C.red],
          ["Honeypots",apis.filter(a=>a.honeypot).length,C.green],
          ["ML At-Risk",apis.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active").length,C.amber],
        ].map(([k,v,c])=>(
          <div key={k} style={{background:C.panel,border:`1px solid ${C.border}`,
            borderRadius:5,padding:"10px 16px",display:"flex",gap:10,alignItems:"center"}}>
            <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
              color:C.dim,letterSpacing:2,flex:1,textTransform:"uppercase"}}>{k}</span>
            <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:22,
              fontWeight:900,color:c}}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{display:"flex",gap:10,marginBottom:16}}>
        <Btn variant="danger" sm onClick={loadAtkPaths}>⚡ Show Attack Paths</Btn>
        <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
          color:C.dim,alignSelf:"center"}}>
          Visualizes attacker movement from zombie entry points
        </span>
      </div>
      {!apis.length?(
        <Empty icon="◎" msg="Run a scan to visualise the API topology."/>
      ):(
        <Panel title="API Topology — Force Graph" icon="⬡"
          meta="Interactive · Click nodes · Particles=data flow · Amber=ML at-risk">
          <Graph apis={apis} onPick={setPicked} picked={picked}/>
        </Panel>
      )}
      {showAtkPaths&&atkPaths.length>0&&(
        <Panel title="Attack Path Analysis" icon="⚡"
          accent={C.red} meta={`${atkPaths.length} entry points`}>
          <div style={{padding:16}}>
            {atkPaths.map((p,i)=>(
              <div key={i} style={{background:`${C.red}06`,border:`1px solid ${C.red}25`,
                borderRadius:4,padding:"12px 16px",marginBottom:10}}>
                <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                    color:C.red,fontWeight:700}}>ENTRY: {p.entry_point}</span>
                  {p.financial_reach&&(
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
                      color:C.amber,background:`${C.amber}15`,
                      border:`1px solid ${C.amber}40`,padding:"2px 7px",borderRadius:3}}>
                      ⚠ FINANCIAL REACH
                    </span>
                  )}
                  <span style={{marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",
                    fontSize:8,color:C.dim}}>Depth: {p.depth} hops</span>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:6,flexWrap:"wrap"}}>
                  {p.attack_chain.map((path,j)=>(
                    <span key={j} style={{display:"flex",alignItems:"center",gap:6}}>
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
                        padding:"3px 8px",borderRadius:3,
                        background:j===0?`${C.red}18`:C.bg,
                        color:j===0?C.red:C.dim,
                        border:`1px solid ${j===0?C.red+"33":C.border}`}}>
                        {path.split("/").pop()}
                      </span>
                      {j<p.attack_chain.length-1&&(
                        <span style={{color:C.border,fontSize:12}}>→</span>
                      )}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
      {pickedApi&&(
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginTop:16}}>
          <Panel title="Node Inspector"
            icon={pickedApi.honeypot?"🍯":pickedApi.status==="zombie"?"☠":"◈"}
            meta={pickedApi.path} accent={sColor(pickedApi.status)}>
            <div style={{padding:16}}>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
                {[
                  {k:"Status",v:<Badge status={pickedApi.status}/>,c:sColor(pickedApi.status)},
                  {k:"Risk Score",v:`${pickedApi.risk||0}/100`,c:pickedApi.risk>=70?C.red:C.neon},
                  {k:"ML Zombie %",v:`${(pickedApi.ml_zombie_probability||0).toFixed(1)}%`,
                    c:(pickedApi.ml_zombie_probability||0)>=75?C.red:
                      (pickedApi.ml_zombie_probability||0)>=50?C.amber:C.green},
                  {k:"Layer",v:pickedApi.layer,c:C.neon2},
                  {k:"Owner",v:pickedApi.owner||"unknown",c:C.text},
                  {k:"Auth",v:pickedApi.auth?"✓ YES":"✗ NO",c:pickedApi.auth?C.green:C.red},
                  {k:"TLS",v:pickedApi.enc?"✓ YES":"✗ NO",c:pickedApi.enc?C.green:C.red},
                  {k:"Calls/Day",v:(pickedApi.calls_per_day||0).toLocaleString(),c:C.neon2},
                ].map(d=>(
                  <div key={d.k} style={{background:C.bg,border:`1px solid ${C.border}`,
                    borderRadius:4,padding:"10px 12px",borderTop:`1px solid ${d.c}44`}}>
                    <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
                      color:C.dim,letterSpacing:2,marginBottom:5}}>{d.k}</div>
                    <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,
                      fontWeight:700,color:d.c}}>
                      {typeof d.v==="object"?d.v:String(d.v)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Panel>
          <Panel title="OWASP Exposure" icon="⚠" accent={C.red}>
            <OWASPPanel apis={[pickedApi]}/>
          </Panel>
        </div>
      )}
    </div>
  );
}

function PageLogs({atkLogs,hpLogs}){
  const[tab,setTab]=useState("attacks");
  const sevC=s=>s==="CRITICAL"?C.red:s==="HIGH"?C.orange:C.amber;
  const logBox={background:C.bg,border:`1px solid ${C.border}`,borderRadius:4,padding:14,
    fontFamily:"'JetBrains Mono',monospace",fontSize:9,maxHeight:360,overflowY:"auto",lineHeight:1.9};
  return(
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:16}}>
        {[["Attack Events",atkLogs.length,C.red],
          ["Breaches",atkLogs.filter(l=>l.outcome==="BREACH").length,C.red],
          ["Blocked",atkLogs.filter(l=>l.outcome==="BLOCKED").length,C.green],
          ["HP Captures",hpLogs.length,C.neon],
        ].map(([k,v,c])=>(
          <div key={k} style={{background:C.panel,border:`1px solid ${C.border}`,
            borderRadius:5,padding:"10px 16px",display:"flex",gap:10,alignItems:"center"}}>
            <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:8,
              color:C.dim,letterSpacing:2,flex:1,textTransform:"uppercase"}}>{k}</span>
            <span style={{fontFamily:"'Orbitron',sans-serif",fontSize:24,
              fontWeight:900,color:c}}>{v}</span>
          </div>
        ))}
      </div>
      <div style={{display:"flex",gap:8,marginBottom:16}}>
        {[["attacks","⚡ Attack Log"],["honeypot","🍯 Honeypot Intel"],["threats","🌐 Threat Feed"]].map(([id,lbl])=>(
          <button key={id} onClick={()=>setTab(id)}
            style={{padding:"7px 18px",borderRadius:4,cursor:"pointer",border:"none",
              transition:"all .15s",fontFamily:"'JetBrains Mono',monospace",
              fontSize:9,letterSpacing:1,
              background:tab===id?C.neon2:"transparent",
              color:tab===id?C.bg:C.muted,
              boxShadow:tab===id?`0 0 14px ${C.neon2}44`:"none"}}>{lbl}</button>
        ))}
      </div>
      {tab==="attacks"&&(
        <Panel title="Attack Event Log" icon="⚡"
          meta={`${atkLogs.length} events`} accent={C.red}>
          <div style={{padding:16}}>
            {!atkLogs.length?<Empty icon="⚡" msg="No attacks yet. Go to Endpoint Analysis."/>:(
              <div style={logBox}>
                {[...atkLogs].reverse().map((log,i)=>(
                  <div key={i} style={{borderBottom:`1px solid ${C.border}44`,
                    paddingBottom:10,marginBottom:10}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:5,flexWrap:"wrap"}}>
                      <span style={{fontSize:7,color:C.dim}}>#{log.id} · {log.ts}</span>
                      <SevBadge sev={log.sev}/>
                      {log.owasp&&<span style={{fontFamily:"'JetBrains Mono',monospace",
                        fontSize:8,color:C.neon2,background:`${C.neon}10`,
                        padding:"1px 5px",borderRadius:2,border:`1px solid ${C.neon}28`}}>
                        {log.owasp}</span>}
                      {log.cve&&log.cve!=="N/A"&&<span style={{fontFamily:"'JetBrains Mono',monospace",
                        fontSize:7,color:C.orange,background:`${C.orange}10`,
                        padding:"1px 5px",borderRadius:2,border:`1px solid ${C.orange}28`}}>
                        {log.cve}</span>}
                      <span style={{marginLeft:"auto",fontSize:9,fontWeight:700,
                        color:log.outcome==="BREACH"?C.red:log.outcome==="TRAPPED"?C.neon:C.green}}>
                        ■ {log.outcome}
                      </span>
                    </div>
                    {[["ATTACKER IP",log.ip,C.red],["TARGET",log.path,C.text],
                      ["TYPE",log.type,sevC(log.sev)],["VECTOR",log.vec,C.muted],
                      ["DETAIL",log.detail,C.text],
                    ].map(([k,v,c])=>(
                      <div key={k} style={{display:"flex",gap:12,marginBottom:2}}>
                        <span style={{color:C.neon2,minWidth:100}}>{k}</span>
                        <span style={{color:c}}>{v}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        </Panel>
      )}
      {tab==="honeypot"&&(
        <Panel title="Honeypot Intel Feed" icon="🍯"
meta={${hpLogs.length} captures} accent={C.green}>

{!hpLogs.length?:(

{[...hpLogs].reverse().map((log,i)=>(
<div key={i} style={{borderBottom:1px solid ${C.border}44,
paddingBottom:10,marginBottom:10}}>

CAPTURE #{hpLogs.length-i} · {log.ts}
{log.dwell&&DWELL: {log.dwell}min}

{[["ATTACKER IP",log.ip,C.red],["ACTION",log.action,C.orange],
["STATUS","Trapped in honeypot",C.green],["INTEL CAPTURED",log.data,C.neon],
].map(([k,v,c])=>(
<div key={k} style={{display:"flex",gap:12,marginBottom:2}}>
{k}
{v}

))}

))}

)}


)}
{tab==="threats"&&(



)}

);
}
function PageOWASP({apis}){
return(

<div style={{marginBottom:16,fontFamily:"'JetBrains Mono',monospace",
fontSize:9,color:C.dim,lineHeight:1.8,letterSpacing:.3}}>
OWASP API Security Top 10 (2023) maps the most critical API security risks.
NECROS X checks all 10 categories in real-time against your scanned endpoints.

<div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>

{apis.length?:
}


{apis.length?:
}



);
}
function PageAI({apis}){
return(
<div style={{height:"calc(100vh - 210px)",display:"flex",flexDirection:"column"}}>
<div style={{marginBottom:14,fontFamily:"'JetBrains Mono',monospace",
fontSize:9,color:C.dim,letterSpacing:.3,lineHeight:1.8}}>
NECROS AI v6.0 — powered by{" "}
GradientBoosting ML
{" "}+{" "}
<span style={{color:"#cc88ff"}}>Claude claude-sonnet-4-5
{" "}(when ANTHROPIC_API_KEY is set).

<div style={{flex:1,background:C.panel,border:1px solid ${C.border},borderRadius:6,
overflow:"hidden",display:"flex",flexDirection:"column",minHeight:0}}>
<div style={{padding:"12px 20px",borderBottom:1px solid ${C.border},
display:"flex",alignItems:"center",gap:10,
background:"rgba(0,0,0,.32)",position:"relative"}}>
<div style={{position:"absolute",bottom:0,left:0,width:64,height:1,
background:C.plasma,opacity:.6}}/>
🤖
<span style={{fontFamily:"'Rajdhani',sans-serif",fontWeight:700,
fontSize:13,letterSpacing:1,color:C.text,textTransform:"uppercase"}}>
NECROS AI — Security Analyst

<span style={{marginLeft:"auto",fontFamily:"'JetBrains Mono',monospace",
fontSize:9,padding:"2px 8px",borderRadius:3,
background:${C.plasma}14,color:"#cc88ff",
border:1px solid ${C.plasma}33}}>GradientBoosting + Claude claude-sonnet-4-5






);
}
function PageTerminal({apis,onScan,target}){
return(
<div style={{height:"calc(100vh - 180px)",display:"flex",flexDirection:"column"}}>
<div style={{marginBottom:14,fontFamily:"'JetBrains Mono',monospace",
fontSize:9,color:C.dim,letterSpacing:.3,lineHeight:1.8}}>
Type{" "}'help'{" "}for all commands.
Try{" "}predict,{" "}
autodefend,{" "}
paths.
Use{" "}↑↓{" "}for history.





);
}
export default function App(){
const[booted,setBooted]=useState(false);
const[page,setPage]=useState("dashboard");
const[apis,setApis]=useState([]);
const[sum,setSum]=useState(null);
const[scanning,setScanning]=useState(false);
const[prog,setProg]=useState(0);
const[target,setTarget]=useState("https://api.acme-corp.io");
const[atkLogs,setAtkLogs]=useState([]);
const[hpLogs,setHpLogs]=useState([]);
const[demoStep,setDemoStep]=useState(0);
const[alerts,setAlerts]=useState([]);
const[clock,setClock]=useState("");
const[feedIdx,setFeedIdx]=useState(0);
useEffect(()=>{
const t=setInterval(()=>setClock(
new Date().toISOString().slice(0,19).replace("T"," ")+" UTC"),1000);
return()=>clearInterval(t);
},[]);
useEffect(()=>{
const t=setInterval(()=>setFeedIdx(i=>(i+1)%THREAT_FEED.length),4500);
return()=>clearInterval(t);
},[]);
useEffect(()=>{
const h=e=>{
if(e.target.tagName==="INPUT")return;
if(e.key==="s"||e.key==="S")doScan();
if(e.key==="1")setPage("dashboard");if(e.key==="2")setPage("details");
if(e.key==="3")setPage("graph");   if(e.key==="4")setPage("predict");
if(e.key==="5")setPage("owasp");   if(e.key==="6")setPage("logs");
if(e.key==="7")setPage("ai");      if(e.key==="8")setPage("terminal");
if(e.key==="9")setPage("architecture");
};
window.addEventListener("keydown",h);
return()=>window.removeEventListener("keydown",h);
},[]);
const downloadPDF=useCallback(async()=>{
try{
const r=await fetch(${API}/report/pdf);
if(r.ok){
const blob=await r.blob();
const url=URL.createObjectURL(blob);
const a=document.createElement("a");
a.href=url;a.download="necros-x-report.pdf";a.click();
URL.revokeObjectURL(url);
}
}catch{
alert("Start the backend server to download PDF reports.");
}
},[]);
const doScan=useCallback(async(overrideTarget)=>{
const t=overrideTarget||target;
if(scanning||!t.trim())return;
setScanning(true);setProg(0);setApis([]);
setSum(null);setAtkLogs([]);setHpLogs([]);
setAlerts([]);setDemoStep(0);
for(let p=0;p<=100;p+=rnd(7,14)){
await new Promise(r=>setTimeout(r,rnd(80,220)));
setProg(Math.min(p,100));
}
try{
const resp=await fetch(${API}/scan,{
method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({target_url:t}),
});
if(resp.ok){
const data=await resp.json();
const mapped=data.apis.map(a=>({
...a,risk:a.risk_score||a.risk||0,
auth:a.auth,enc:a.encrypted||a.enc,
days:a.inactivity_days||a.days||0,
seen:a.last_seen||a.seen||"Unknown",
conns:a.connections||a.conns||[],
calls_per_day:a.calls_per_day||0,
ml_zombie_probability:a.ml_zombie_probability||0,
ml_prediction_30d:a.ml_prediction_30d||0,
ml_prediction_60d:a.ml_prediction_60d||0,
ml_prediction_90d:a.ml_prediction_90d||0,
ml_risk_level:a.ml_risk_level||"LOW",
ml_recommendation:a.ml_recommendation||"",
}));
setApis(mapped);
setSum({total:data.summary.total,active:data.summary.active,
zombie:data.summary.zombie,dep:data.summary.deprecated,
avg:data.summary.avg_risk,tl:data.summary.threat_level,
ml_high:data.summary.ml_high_risk||0});
setAlerts(data.alerts||[]);
}else throw new Error();
}catch{
const built=mkApis();
const zc=built.filter(a=>a.status==="zombie").length;
const dc=built.filter(a=>a.status==="deprecated").length;
const avg=Math.round(built.reduce((s,a)=>s+a.risk,0)/built.length);
const mlHigh=built.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active").length;
setApis(built);
setSum({total:built.length,active:built.length-zc-dc,
zombie:zc,dep:dc,avg,ml_high:mlHigh,
tl:avg>60?"CRITICAL":avg>40?"HIGH":"MEDIUM"});
const initAlerts=[
...built.filter(a=>a.status==="zombie").map(a=>({
id:uid(),type:"ZOMBIE_DETECTED",sev:"CRITICAL",path:a.path,
msg:Zombie API: ${a.path} — ${a.days}d inactive,ts:ts(),ack:false,
})),
...built.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active").map(a=>({
id:uid(),type:"ML_ZOMBIE_PREDICTION",sev:"HIGH",path:a.path,
msg:AI predicts ${a.path}: ${a.ml_zombie_probability}% zombie probability,
ts:ts(),ack:false,
})),
];
setAlerts(initAlerts);
}
setScanning(false);setDemoStep(1);
voiceAlert("Scan complete. 2 zombie APIs detected. Threat level critical.");
},[scanning,target]);
const onAck=useCallback((idx)=>{
setAlerts(a=>a.map((al,i)=>i===idx?{...al,ack:true}:al));
},[]);
const tl=sum?.tl||"NONE";
const tlC={CRITICAL:C.red,HIGH:C.orange,MEDIUM:C.amber,NONE:C.green}[tl]||C.green;
const zc=apis.filter(a=>a.status==="zombie").length;
const hc=apis.filter(a=>a.honeypot).length;
const openA=alerts.filter(a=>!a.ack).length;
const NAV=[
{id:"dashboard",   icon:"⬡",lbl:"Dashboard",     key:"1"},
{id:"details",     icon:"◈",lbl:"Endpoint Analyst",key:"2"},
{id:"graph",       icon:"⬡",lbl:"Topology Graph",  key:"3"},
{id:"predict",     icon:"🤖",lbl:"ML Predictions",  key:"4"},
{id:"owasp",       icon:"⚠",lbl:"OWASP Coverage",  key:"5"},
{id:"logs",        icon:"▤",lbl:"Logs & Threats",   key:"6"},
{id:"ai",          icon:"🤖",lbl:"AI Analyst",      key:"7"},
{id:"terminal",    icon:">_",lbl:"Terminal",        key:"8"},
{id:"architecture",icon:"⬡",lbl:"Architecture",    key:"9"},
];
const TITLES={
dashboard:"OVERVIEW",details:"ENDPOINT ANALYSIS",
graph:"TOPOLOGY GRAPH",predict:"ML ZOMBIE PREDICTIONS",
owasp:"OWASP COVERAGE",logs:"LOGS & THREATS",
ai:"AI SECURITY ANALYST",terminal:"HACKER TERMINAL",
architecture:"SYSTEM ARCHITECTURE",
};
return(
<>
<link href={"https://fonts.googleapis.com/css2?"
+"family=Orbitron:wght@700;900"
+"&family=JetBrains+Mono:wght@300;400;700"
+"&family=Rajdhani:wght@400;500;600;700"
+"&display=swap"} rel="stylesheet"/>
{!booted&&<BootScreen onDone={()=>setBooted(true)}/>}
<div style={{display:"flex",height:"100vh",overflow:"hidden",
fontFamily:"'Rajdhani',sans-serif",background:C.bg,color:C.text,
opacity:booted?1:0,transition:"opacity .5s .3s"}}>
{/* SIDEBAR /}
<div style={{width:244,minWidth:244,background:C.bg2,
borderRight:1px solid ${C.border},display:"flex",
flexDirection:"column",position:"relative",overflow:"hidden",flexShrink:0}}>
<div style={{position:"absolute",top:0,right:0,width:1,height:"100%",
background:linear-gradient(180deg,transparent,${C.neon},${C.plasma},transparent),
opacity:.4}}/>
{/ Logo /}
<div style={{padding:"22px 20px 16px",borderBottom:1px solid ${C.border},position:"relative"}}>
<div style={{fontFamily:"'Orbitron',sans-serif",fontSize:19,fontWeight:900,
letterSpacing:3,color:C.neon,
textShadow:0 0 28px ${C.neon}bb,0 0 60px ${C.neon}33}}>NECROS X
<div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:C.dim,
letterSpacing:3,marginTop:8,textTransform:"uppercase"}}>
Zombie API Defense · v6.0

<div style={{position:"absolute",top:22,right:16,display:"flex",gap:4}}>
{[["ML","#cc88ff",C.plasma],[" AI",C.neon,C.neon]].map(([l,c,b])=>(
<div key={l} style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,color:c,
background:${b}14,border:1px solid ${b}44,
padding:"2px 6px",borderRadius:3}}>{l}
))}


{/ Status /}
<div style={{padding:"8px 20px",borderBottom:1px solid ${C.border},
display:"flex",alignItems:"center",gap:8,
fontFamily:"'JetBrains Mono',monospace",fontSize:8,letterSpacing:1}}>
<div style={{width:5,height:5,borderRadius:"50%",background:C.green,
boxShadow:0 0 6px ${C.green},flexShrink:0,animation:"sbPulse 2s infinite"}}/>
<span style={{color:C.green,textTransform:"uppercase"}}>All Systems Nominal
<span style={{marginLeft:"auto",color:C.dim,fontSize:9}}>{clock.slice(11,19)}

{/ Nav /}
<nav style={{flex:1,padding:"12px 10px",overflowY:"auto"}}>
<div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,letterSpacing:3,
color:C.dim,padding:"8px 8px 5px",textTransform:"uppercase"}}>Navigation
{NAV.map(item=>{
const active=page===item.id;
return(
<div key={item.id} onClick={()=>setPage(item.id)}
style={{display:"flex",alignItems:"center",gap:9,padding:"8px 12px",
borderRadius:4,cursor:"pointer",marginBottom:2,
fontFamily:"'Rajdhani',sans-serif",fontSize:12,fontWeight:500,
letterSpacing:.5,color:active?C.neon:C.muted,
background:active?${C.neon}0d:"transparent",
border:1px solid ${active?C.neon+"44":"transparent"},
borderLeft:active?2px solid ${C.neon}:"2px solid transparent",
transition:"all .18s",
textShadow:active?0 0 14px ${C.neon}55:"none"}}>
{item.icon}
{item.lbl}
{item.id==="details"&&zc>0&&(
<span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
background:${C.red}20,color:C.red,border:1px solid ${C.red}44,
padding:"1px 5px",borderRadius:3,animation:"badgePulse 1.5s infinite"}}>
{zc}

)}
{item.id==="predict"&&(
<span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
background:${C.plasma}14,color:"#cc88ff",
border:1px solid ${C.plasma}33,padding:"1px 5px",borderRadius:3}}>ML
)}
{item.id==="logs"&&openA>0&&(
<span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:9,
background:${C.orange}16,color:C.orange,
border:1px solid ${C.orange}44,padding:"1px 5px",borderRadius:3}}>
{openA}

)}
<span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:7,
color:C.dim,marginLeft:2}}>{item.key}

);
})}

{/ Stats /}
<div style={{padding:"12px 18px",borderTop:1px solid ${C.border},
background:"rgba(0,0,0,.3)",fontFamily:"'JetBrains Mono',monospace",fontSize:9}}>
{[
["APIs Scanned",apis.length,C.neon],
["Zombies",zc,C.red],
["ML At-Risk",apis.filter(a=>(a.ml_zombie_probability||0)>=50&&a.status==="active").length,C.amber],
["Honeypots",hc,C.green],
["Attacks",atkLogs.length,C.orange],
["Open Alerts",openA,openA>0?C.red:C.dim],
].map(([k,v,c])=>(
<div key={k} style={{display:"flex",justifyContent:"space-between",marginBottom:6,letterSpacing:.3}}>
{k}
{v||"—"}

))}
<div style={{marginTop:8,paddingTop:8,borderTop:1px solid ${C.border},
fontSize:7,color:C.dim,letterSpacing:1}}>S=scan · 1-9=pages

{/ Threat ticker /}
<div style={{padding:"7px 14px",borderTop:1px solid ${C.border},
background:"rgba(255,26,60,.05)",fontFamily:"'JetBrains Mono',monospace",
fontSize:7,color:C.red,letterSpacing:.5,
overflow:"hidden",whiteSpace:"nowrap",textOverflow:"ellipsis"}}>
⚠ {THREAT_FEED[feedIdx]}


{/ MAIN /}
<div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
{/ Topbar /}
<div style={{height:54,flexShrink:0,background:C.bg2,
borderBottom:1px solid ${C.border},display:"flex",alignItems:"center",
padding:"0 26px",gap:18,position:"relative"}}>
<div style={{position:"absolute",bottom:0,left:0,right:0,height:1,
background:linear-gradient(90deg,transparent,${C.neon2},${C.plasma},transparent),
opacity:.2}}/>

<div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,
display:"flex",gap:8,alignItems:"center"}}>
NECROS X
›
{TITLES[page]}


<div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:12}}>
{sum&&(
<button onClick={downloadPDF}
style={{padding:"5px 14px",borderRadius:4,
border:1px solid ${C.neon}44,background:${C.neon}10,
color:C.neon,cursor:"pointer",
fontFamily:"'JetBrains Mono',monospace",fontSize:9,letterSpacing:1}}>
↓ PDF REPORT

)}
{sum&&(
<div style={{display:"flex",alignItems:"center",gap:8,padding:"5px 14px",
borderRadius:4,background:${tlC}12,color:tlC,
border:1px solid ${tlC}44,
fontFamily:"'JetBrains Mono',monospace",fontSize:10,
fontWeight:700,letterSpacing:2,
boxShadow:tl==="CRITICAL"?0 0 20px ${C.red}30:"none",
animation:tl==="CRITICAL"?"critPulse 1.8s ease-in-out infinite":"none"}}>
<div style={{width:5,height:5,borderRadius:"50%",background:tlC,
boxShadow:0 0 6px ${tlC},animation:"sbPulse 1.5s infinite"}}/>
THREAT : {tl}

)}
{openA>0&&(
<div style={{display:"flex",alignItems:"center",gap:6,padding:"5px 12px",
borderRadius:4,background:${C.red}10,color:C.red,
border:1px solid ${C.red}40,cursor:"pointer",
fontFamily:"'JetBrains Mono',monospace",fontSize:10,fontWeight:700,
letterSpacing:1,animation:"badgePulse 1.5s infinite"}}
onClick={()=>setPage("dashboard")}>
🔔 {openA}

)}
<span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.muted,
borderLeft:1px solid ${C.border},paddingLeft:14,letterSpacing:.5}}>
{clock}



{/ Content */}
<div style={{flex:1,overflowY:"auto",padding:"20px 26px"}}>
{page==="dashboard"&&}
{page==="details"&&}
{page==="graph"&&}
{page==="predict"&&}
{page==="owasp"&&}
{page==="logs"&&}
{page==="ai"&&}
{page==="terminal"&&}
{page==="architecture"&&}



{@keyframes sbPulse{0%,100%{opacity:1;box-shadow:0 0 6px #00ffaa}50%{opacity:.6;box-shadow:0 0 12px #00ffaa}} @keyframes critPulse{0%,100%{box-shadow:0 0 20px rgba(255,26,60,.2)}50%{box-shadow:0 0 36px rgba(255,26,60,.55)}} @keyframes badgePulse{0%,100%{opacity:1}50%{opacity:.5}} @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}} @keyframes bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}} @keyframes blink{0%,100%{opacity:1}50%{opacity:0}} ::-webkit-scrollbar{width:3px;height:3px} ::-webkit-scrollbar-track{background:#01060e} ::-webkit-scrollbar-thumb{background:#0078b8;border-radius:2px} *{box-sizing:border-box;margin:0;padding:0} input,button,textarea{font-family:inherit}}
</>
);
}
