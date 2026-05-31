import React, { useState, useEffect, useRef, useCallback, createContext, useContext } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line } from 'recharts';
import ForceGraph2D from 'react-force-graph-2d';
import { jsPDF } from 'jspdf';
import html2canvas from 'html2canvas';

// --- Inline Tailwind classes via <style> (or use CDN in index.html) ---
// We'll include Tailwind CDN in index.html for simplicity.

/* ==================== API Helpers ==================== */
const API_BASE = import.meta.env.VITE_API_BASE || '';
const TOKEN_KEY = 'necros_token';
const DEFAULT_TOKEN = 'necros-demo-token-2024';
const getToken = () => localStorage.getItem(TOKEN_KEY) || DEFAULT_TOKEN;
async function request(endpoint, options={}) {
  const token = getToken();
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: { 'Content-Type':'application/json', 'Authorization':`Bearer ${token}`, ...options.headers }
  });
  if (!res.ok) throw new Error((await res.json().catch(()=>({detail:'Error'}))).detail);
  return res.json();
}
const api = {
  scan: (url)=>request('/api/scan',{method:'POST',body:JSON.stringify({base_url:url})}),
  getRegistry:(l,s)=>{ const p=new URLSearchParams(); if(l)p.append('lifecycle',l); if(s)p.append('search',s); return request(`/api/registry?${p}`);},
  getStats:()=>request('/api/stats'),
  predict:(id)=>request(`/api/predict/${id}`),
  attackPath:()=>request('/api/attack-path'),
  defend:(ids=[])=>request('/api/defend',{method:'POST',body:JSON.stringify({target_api_ids:ids})}),
  honeypotEvents:()=>request('/api/honeypot-events'),
  intel:()=>request('/api/intel'),
  aiAssistant:(msg)=>request('/api/ai-assistant',{method:'POST',body:JSON.stringify({message:msg})}),
};

/* ==================== Context ==================== */
const AppCtx = createContext();
const useApp = ()=>useContext(AppCtx);

function AppProvider({children}){
  const [stats, setStats] = useState({});
  const [registry, setRegistry] = useState([]);
  const [attackGraph, setAttackGraph] = useState({nodes:[],links:[]});
  const [honeypotEvents, setHoneypotEvents] = useState([]);
  const [intel, setIntel] = useState([]);
  const [selectedApi, setSelectedApi] = useState(null);
  const [forecastData, setForecastData] = useState(null);
  const [notif, setNotif] = useState(null);
  const [online, setOnline] = useState(true);
  const [applMode, setApplMode] = useState(false);
  const [applMetrics, setApplMetrics] = useState({
    cpu:12,mem:34,uptime:'14d 7h',packets:2349012,throughput:'1.2 Gbps',temperature:42,disk:78
  });

  useEffect(()=>{
    if(applMode){
      const iv = setInterval(()=>{
        setApplMetrics(p=>({...p,
          cpu:Math.min(100,Math.max(0,p.cpu+(Math.random()*10-5))),
          mem:Math.min(100,Math.max(0,p.mem+(Math.random()*5-2))),
          throughput:`${(Math.random()*2+0.5).toFixed(1)} Gbps`,
          packets:p.packets+Math.floor(Math.random()*1000),
          temperature:Math.floor(40+Math.random()*10)
        }));
      },2000);
      return ()=>clearInterval(iv);
    }
  },[applMode]);

  const notify = useCallback((msg,type='success')=>{ setNotif({msg,type}); setTimeout(()=>setNotif(null),5000); },[]);

  const fetchStats = useCallback(async ()=>{
    try{ setStats(await api.getStats()); setOnline(true); }catch{ notify('Backend offline','error'); setOnline(false); }
  },[notify]);

  const fetchRegistry = useCallback(async (lifecycle,search)=>{
    try{ setRegistry(await api.getRegistry(lifecycle,search)); }catch{ notify('Registry fetch failed','error'); }
  },[notify]);

  const fetchAttackGraph = async ()=>{ try{ setAttackGraph(await api.attackPath()); }catch{} };
  const fetchHoneypot = async ()=>{ try{ setHoneypotEvents(await api.honeypotEvents()); }catch{} };
  const fetchIntel = async ()=>{ try{ setIntel(await api.intel()); }catch{} };

  const handleScan = async (url)=>{
    try{ const r=await api.scan(url); notify(r.message); fetchRegistry(); fetchStats(); fetchAttackGraph(); }catch(e){ notify(e.message,'error'); }
  };
  const handleDefend = async (ids=[])=>{
    try{ const r=await api.defend(ids); notify(r.message); fetchRegistry(); fetchStats(); fetchHoneypot(); fetchAttackGraph(); }catch(e){ notify(e.message,'error'); }
  };
  const handlePredict = async (id)=>{
    try{ const d=await api.predict(id); setForecastData(d); setSelectedApi(d); }catch(e){ notify('Prediction failed','error'); }
  };

  useEffect(()=>{ fetchStats(); fetchRegistry(); fetchAttackGraph(); fetchHoneypot(); fetchIntel(); },[]);

  return (
    <AppCtx.Provider value={{
      stats, registry, attackGraph, honeypotEvents, intel, selectedApi, forecastData, notif, online, applMode, setApplMode, applMetrics,
      notify, fetchStats, fetchRegistry, fetchAttackGraph, fetchHoneypot, fetchIntel, handleScan, handleDefend, handlePredict, setSelectedApi
    }}>
      {children}
    </AppCtx.Provider>
  );
}

/* ==================== Components ==================== */
function NotificationToast(){
  const {notif,notify} = useApp();
  if(!notif) return null;
  return (
    <div style={{position:'fixed',top:16,right:16,zIndex:50,maxWidth:320}}>
      <div style={{padding:'8px 12px',borderRadius:6,background:notif.type==='error'?'#7f1d1d':'#064e3b',color:'#fff',display:'flex',justifyContent:'space-between'}}>
        <span style={{fontSize:14}}>{notif.msg}</span>
        <button onClick={()=>notify(null)} style={{marginLeft:8,color:'#ccc'}}>&times;</button>
      </div>
    </div>
  );
}

function BootSequence({onDone}){
  const [logs,setLogs]=useState([]);
  const [pct,setPct]=useState(0);
  useEffect(()=>{
    const steps=["Initializing...","Loading kernel...","Encrypting channel...","Training ML...","Seeding registry...","Attack path online.","Threat intel synced.","Honeypots armed.","READY."];
    let i=0;
    const iv=setInterval(()=>{
      if(i<steps.length){ setLogs(p=>[...p,steps[i]]); setPct(((i+1)/steps.length)*100); i++; }
      else{ clearInterval(iv); setTimeout(onDone,500); }
    },350);
    return ()=>clearInterval(iv);
  },[onDone]);
  return (
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',height:'100vh',background:'black',color:'#4ade80',fontFamily:'monospace'}}>
      <h1 style={{fontSize:48,textShadow:'0 0 10px #3b82f6'}}>NECROS X</h1>
      <div style={{width:320,height:8,background:'#333',borderRadius:4,margin:'16px 0'}}>
        <div style={{width:`${pct}%`,height:'100%',background:'#22c55e',borderRadius:4,transition:'width 0.3s'}}></div>
      </div>
      <div style={{width:320,maxHeight:200,overflowY:'auto',background:'#111',padding:12,borderRadius:6,border:'1px solid #166534',fontSize:12}}>
        {logs.map((l,i)=><p key={i}>[{new Date().toLocaleTimeString()}] {l}</p>)}
      </div>
    </div>
  );
}

function Terminal({onCmd}){
  const [cmd,setCmd]=useState('');
  const [hist,setHist]=useState([]);
  const submit = e=>{ e.preventDefault(); if(!cmd.trim())return; setHist(p=>[...p,`> ${cmd}`]); onCmd(cmd); setCmd(''); };
  return (
    <div style={{background:'#1f2937',borderRadius:6,border:'1px solid #374151',fontFamily:'monospace',fontSize:13}}>
      <div style={{height:128,overflowY:'auto',padding:8,color:'#86efac'}}>{hist.map((l,i)=><p key={i}>{l}</p>)}</div>
      <form onSubmit={submit} style={{display:'flex',borderTop:'1px solid #374151',padding:8}}>
        <span style={{color:'#4ade80',marginRight:8}}>$</span>
        <input value={cmd} onChange={e=>setCmd(e.target.value)} style={{flex:1,background:'transparent',border:'none',outline:'none',color:'#86efac'}} placeholder="Type command..." />
      </form>
    </div>
  );
}

/* ==================== Pages ==================== */
const LifecycleColor = s=> ({active:'#10b981',deprecated:'#f59e0b',orphaned:'#f97316',zombie:'#ef4444'}[s]||'#9ca3af');

function Dashboard(){
  const {stats,registry,applMode,applMetrics,handleScan,handleDefend,notify} = useApp();
  const [url,setUrl]=useState('https://api.examplebank.com');
  const pie = [{name:'Active',value:stats.active||0},{name:'Deprecated',value:stats.deprecated||0},{name:'Orphaned',value:stats.orphaned||0},{name:'Zombie',value:stats.zombie||0}];
  const bar = registry.slice(0,8).map(a=>({name:a.path.slice(0,20),risk:a.risk_score}));
  const exportPDF = async ()=>{
    const el=document.getElementById('dash');
    const c=await html2canvas(el,{backgroundColor:'#0a0f1e'});
    const pdf=new jsPDF(); pdf.addImage(c.toDataURL('image/png'),'PNG',0,0,210,297*(c.height/c.width));
    pdf.save('necrosx-report.pdf'); notify('PDF downloaded');
  };
  useEffect(()=>{ if(stats.critical_threats>0&&window.speechSynthesis) window.speechSynthesis.speak(new SpeechSynthesisUtterance(`Warning: ${stats.critical_threats} threats.`)); },[stats.critical_threats]);
  return (
    <div id="dash">
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:16}}>
        <h2 style={{fontSize:24,color:'#60a5fa'}}>Executive Dashboard</h2>
        <div style={{display:'flex',gap:8}}>
          <input value={url} onChange={e=>setUrl(e.target.value)} style={{background:'#1f2937',border:'1px solid #374151',borderRadius:4,padding:'4px 8px',fontSize:13,color:'#e5e7eb'}} placeholder="Base URL" />
          <button id="scan-btn" onClick={()=>handleScan(url)} style={{background:'#2563eb',border:'none',borderRadius:4,padding:'6px 14px',color:'white',cursor:'pointer'}}>Scan</button>
          {applMode?<button id="defend-btn" onClick={()=>handleDefend()} style={{background:'#7f1d1d',border:'2px solid #ef4444',borderRadius:6,padding:'6px 16px',color:'white',fontWeight:'bold',display:'flex',alignItems:'center',gap:4}}>🔒 DEFEND (KEY-ARMED)</button>
          :<button id="defend-btn" onClick={()=>handleDefend()} style={{background:'#b91c1c',border:'none',borderRadius:4,padding:'6px 14px',color:'white',cursor:'pointer'}}>AUTO-DEFEND</button>}
          <button onClick={exportPDF} style={{background:'#4b5563',border:'none',borderRadius:4,padding:'6px 14px',color:'white',cursor:'pointer'}}>Export PDF</button>
        </div>
      </div>
      {applMode&&<div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:8,marginBottom:16}}>
        {[['CPU',`${applMetrics.cpu.toFixed(0)}%`],['Memory',`${applMetrics.mem.toFixed(0)}%`],['Throughput',applMetrics.throughput],['Packets',applMetrics.packets.toLocaleString()],['Uptime',applMetrics.uptime]].map(([l,v])=><div key={l} style={{background:'#111827',padding:8,borderRadius:6,border:'1px solid #374151',textAlign:'center'}}><div style={{fontSize:11,color:'#9ca3af'}}>{l}</div><div style={{fontSize:18,color:'#60a5fa'}}>{v}</div></div>)}
      </div>}
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:16}}>
        {[['Total',stats.total,'#60a5fa'],['Active',stats.active,'#10b981'],['Deprecated',stats.deprecated,'#f59e0b'],['Orphaned',stats.orphaned,'#f97316'],['Zombie',stats.zombie,'#ef4444'],['Critical',stats.critical_threats,'#dc2626'],['Posture',`${stats.security_posture}%`,'#93c5fd']].map(([l,v,c])=><div key={l} style={{background:'#111827',padding:12,borderRadius:8,border:'1px solid #374151'}}><div style={{fontSize:13,color:'#9ca3af'}}>{l}</div><div style={{fontSize:24,fontWeight:'bold',color:c}}>{v}</div></div>)}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <div style={{background:'#111827',padding:12,borderRadius:8,border:'1px solid #374151'}}>
          <h3>Lifecycle Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart><Pie data={pie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label>{pie.map((_,i)=><Cell key={i} fill={['#10b981','#f59e0b','#f97316','#ef4444'][i]}/>)}</Pie><Tooltip/></PieChart>
          </ResponsiveContainer>
        </div>
        <div style={{background:'#111827',padding:12,borderRadius:8,border:'1px solid #374151'}}>
          <h3>Top Risk APIs</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={bar}><CartesianGrid strokeDasharray="3 3" stroke="#374151"/><XAxis dataKey="name" stroke="#9ca3af" fontSize={10}/><YAxis stroke="#9ca3af"/><Tooltip/><Bar dataKey="risk" fill="#3b82f6" radius={[4,4,0,0]}/></BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div style={{marginTop:12,fontSize:11,color:'#6b7280'}}>Keys: S=scan D=defend 0-9=navigate</div>
    </div>
  );
}

function Registry(){
  const {registry,fetchRegistry,handlePredict} = useApp();
  const [lifecycle,setLifecycle]=useState('');
  const [search,setSearch]=useState('');
  useEffect(()=>{ fetchRegistry(lifecycle,search); },[lifecycle,search,fetchRegistry]);
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>API Registry</h2>
      <div style={{display:'flex',gap:8,marginBottom:12}}>
        <select value={lifecycle} onChange={e=>setLifecycle(e.target.value)} style={{background:'#1f2937',border:'1px solid #374151',borderRadius:4,padding:'4px 8px',color:'#e5e7eb',fontSize:13}}>
          <option value="">All</option><option value="active">Active</option><option value="deprecated">Deprecated</option><option value="orphaned">Orphaned</option><option value="zombie">Zombie</option>
        </select>
        <input placeholder="Search..." value={search} onChange={e=>setSearch(e.target.value)} style={{flex:1,background:'#1f2937',border:'1px solid #374151',borderRadius:4,padding:'4px 8px',color:'#e5e7eb',fontSize:13}} />
      </div>
      <div style={{overflowX:'auto',background:'#111827',borderRadius:8,border:'1px solid #374151'}}>
        <table style={{width:'100%',fontSize:13}}>
          <thead><tr style={{background:'#1f2937',color:'#d1d5db'}}><th style={{padding:8,textAlign:'left'}}>Endpoint</th><th>Owner</th><th>Lifecycle</th><th>Last Used</th><th>Auth</th><th>Exp</th><th>Risk</th><th>Action</th></tr></thead>
          <tbody>
            {registry.map(api=><tr key={api.id} style={{borderTop:'1px solid #374151'}}>
              <td style={{padding:8,fontFamily:'monospace',fontSize:11}}>{api.full_url}</td><td style={{padding:8}}>{api.owner}</td>
              <td style={{padding:8,color:LifecycleColor(api.lifecycle),fontWeight:'bold'}}>{api.lifecycle}</td>
              <td style={{padding:8,fontSize:11}}>{api.last_used?new Date(api.last_used).toLocaleDateString():'N/A'}</td>
              <td>{api.auth_enabled?'✅':'❌'}</td><td>{api.public_exposure_level}/3</td><td style={{fontWeight:'bold'}}>{api.risk_score}</td>
              <td><button onClick={()=>handlePredict(api.id)} style={{background:'#7c3aed',border:'none',borderRadius:4,padding:'2px 8px',color:'white',cursor:'pointer',fontSize:11}}>Forecast</button></td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Forecast(){
  const {selectedApi,forecastData} = useApp();
  if(!selectedApi) return <div style={{textAlign:'center',marginTop:60,color:'#9ca3af'}}><h2>ML Forecast</h2><p>Select an API from Registry.</p></div>;
  const data = [
    {label:'Current',risk:forecastData?.current_risk??selectedApi.risk_score},
    {label:'30d',risk:forecastData?.risk_30d},{label:'60d',risk:forecastData?.risk_60d},{label:'90d',risk:forecastData?.risk_90d}
  ];
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>Forecast: {selectedApi.full_url}</h2>
      <div style={{background:'#111827',padding:16,borderRadius:8,border:'1px solid #374151'}}>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16}}>
          <div><p>Lifecycle: <b>{selectedApi.lifecycle}</b></p><p>Zombie Prob: <b>{selectedApi.zombie_probability?.toFixed(2)}</b></p><p>Confidence: <b>{selectedApi.confidence?.toFixed(2)}</b></p></div>
          <div><p>Current Risk: <b style={{fontSize:24}}>{forecastData?.current_risk??selectedApi.risk_score}</b></p></div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data}><CartesianGrid stroke="#374151"/><XAxis dataKey="label" stroke="#9ca3af"/><YAxis domain={[0,100]} stroke="#9ca3af"/><Tooltip/><Line type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={3}/></LineChart>
        </ResponsiveContainer>
        <p style={{fontSize:10,color:'#6b7280',marginTop:8}}>SIMULATED FORECAST</p>
      </div>
    </div>
  );
}

function Posture(){
  const {registry} = useApp();
  const high = registry.filter(a=>a.risk_score>70);
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>Security Posture</h2>
      <div style={{display:'grid',gridTemplateColumns:'repeat(2,1fr)',gap:12}}>
        {high.map(api=><div key={api.id} style={{background:'#111827',padding:12,borderRadius:8,border:'1px solid #374151'}}>
          <h4 style={{fontFamily:'monospace',fontSize:14,margin:0}}>{api.path}</h4>
          <p>Auth: <span style={{color:api.auth_enabled?'#10b981':'#ef4444'}}>{api.auth_enabled?'Strong':'Weak'}</span></p>
          <p>Exposure: {['None','Internal','Partner','Public'][api.public_exposure_level]}</p>
          <p>Inactivity risk: {api.traffic_inactivity_score?.toFixed(2)}</p>
          <p>Sensitive access: {api.sensitive_data_access_score?.toFixed(2)}</p>
          <p style={{fontWeight:'bold'}}>Posture: {Math.max(0,100-api.risk_score)}/100</p>
        </div>)}
        {high.length===0&&<p style={{color:'#9ca3af'}}>No high-risk APIs.</p>}
      </div>
    </div>
  );
}

function AttackPath(){
  const {attackGraph} = useApp();
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>Attack Path</h2>
      <div style={{background:'#111827',borderRadius:8,border:'1px solid #374151',height:500}}>
        <ForceGraph2D graphData={attackGraph} nodeLabel="id" nodeColor={n=>n.type==='external'?'#6b7280':n.type==='gateway'?'#3b82f6':n.type==='database'?'#ef4444':n.lifecycle==='zombie'?'#dc2626':n.lifecycle==='orphaned'?'#f97316':n.lifecycle==='deprecated'?'#f59e0b':'#10b981'} linkColor={()=>'#4b5563'} linkDirectionalParticles={2} width={window.innerWidth-280} height={500} />
      </div>
      <p style={{fontSize:10,color:'#6b7280'}}>SIMULATED</p>
    </div>
  );
}

function Honeypot(){
  const {honeypotEvents,fetchHoneypot} = useApp();
  useEffect(()=>{ fetchHoneypot(); const iv=setInterval(fetchHoneypot,10000); return ()=>clearInterval(iv); },[fetchHoneypot]);
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>Honeypot Events</h2>
      <div style={{overflowX:'auto',background:'#111827',borderRadius:8,border:'1px solid #374151'}}>
        <table style={{width:'100%',fontSize:13}}><thead><tr style={{background:'#1f2937'}}><th>Time</th><th>API ID</th><th>Attacker</th><th>Persona</th><th>Payload</th></tr></thead>
          <tbody>{honeypotEvents.map((e,i)=><tr key={i} style={{borderTop:'1px solid #374151'}}><td style={{padding:4}}>{new Date(e.timestamp).toLocaleString()}</td><td style={{fontFamily:'monospace',fontSize:11}}>{e.api_id}</td><td>{e.attacker_ip}</td><td style={{color:'#ef4444'}}>{e.persona}</td><td>{e.payload}</td></tr>)}</tbody>
        </table>
      </div>
      <p style={{fontSize:10,color:'#6b7280'}}>SIMULATED</p>
    </div>
  );
}

function Intel(){
  const {intel,fetchIntel} = useApp();
  useEffect(()=>{ fetchIntel(); },[fetchIntel]);
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>Threat Intel</h2>
      <div style={{display:'flex',flexDirection:'column',gap:8}}>
        {intel.map((i,idx)=><div key={idx} style={{background:'#111827',padding:12,borderRadius:6,border:'1px solid #374151'}}><h4 style={{color:'#60a5fa',margin:0}}>{i.source}</h4><p style={{fontSize:13,color:'#9ca3af'}}>{i.desc||i.description}</p></div>)}
      </div>
    </div>
  );
}

function AIAssistant(){
  const [msg,setMsg]=useState('');
  const [resp,setResp]=useState('');
  const [mode,setMode]=useState('');
  const [loading,setLoading]=useState(false);
  const ask = async ()=>{
    if(!msg.trim())return; setLoading(true);
    try{ const r=await api.aiAssistant(msg); setResp(r.response); setMode(r.mode); }catch{ setResp('Error'); setMode('error'); }
    setLoading(false);
  };
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>AI Analyst</h2>
      <div style={{background:'#111827',padding:12,borderRadius:6,border:'1px solid #374151',minHeight:120,marginBottom:12}}>
        {resp?<div><span style={{fontSize:10,color:'#6b7280'}}>Mode: {mode}</span><p style={{whiteSpace:'pre-wrap'}}>{resp}</p></div>:<p style={{color:'#9ca3af'}}>Ask about zombie APIs or risk mitigation.</p>}
      </div>
      <div style={{display:'flex',gap:8}}>
        <input value={msg} onChange={e=>setMsg(e.target.value)} onKeyDown={e=>e.key==='Enter'&&ask()} style={{flex:1,background:'#1f2937',border:'1px solid #374151',borderRadius:4,padding:6,color:'#e5e7eb'}} placeholder="e.g., Explain zombie API risk" />
        <button onClick={ask} disabled={loading} style={{background:'#2563eb',border:'none',borderRadius:4,padding:'6px 14px',color:'white',cursor:'pointer'}}>{loading?'...':'Ask'}</button>
      </div>
    </div>
  );
}

function Architecture(){
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:16}}>Architecture Comparison</h2>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <div style={{background:'#111827',padding:16,borderRadius:8,border:'1px solid #7f1d1d'}}>
          <h3 style={{color:'#ef4444'}}>BEFORE NECROS X</h3>
          <ul style={{fontSize:14,color:'#d1d5db'}}><li>Unmanaged APIs</li><li>Blind spots</li><li>Delayed detection</li><li>No lifecycle visibility</li></ul>
        </div>
        <div style={{background:'#111827',padding:16,borderRadius:8,border:'1px solid #064e3b'}}>
          <h3 style={{color:'#10b981'}}>AFTER NECROS X</h3>
          <ul style={{fontSize:14,color:'#d1d5db'}}><li>Centralized governance</li><li>AI prediction</li><li>Auto defense</li><li>Continuous monitoring</li></ul>
        </div>
      </div>
    </div>
  );
}

function ApplianceConsole(){
  const {applMetrics,applMode} = useApp();
  const [packets,setPackets]=useState([]);
  useEffect(()=>{
    if(!applMode)return;
    const iv=setInterval(()=>{
      const m=['GET','POST','PUT','DELETE'], paths=['/kyc/verify','/upi/pay','/loan/eligibility','/admin/debug'];
      setPackets(p=>[{time:new Date().toLocaleTimeString(),src:`10.0.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,method:m[Math.floor(Math.random()*4)],path:paths[Math.floor(Math.random()*4)],status:Math.random()>0.8?500:200},...p.slice(0,19)]);
    },800);
    return ()=>clearInterval(iv);
  },[applMode]);
  return (
    <div>
      <h2 style={{fontSize:22,color:'#60a5fa',marginBottom:12}}>Appliance Console</h2>
      <div style={{background:'#111827',padding:16,borderRadius:8,border:'1px solid #374151'}}>
        <div style={{display:'flex',gap:16,marginBottom:16}}>
          <div style={{width:100,height:70,background:'#1f2937',border:'2px solid #4b5563',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center',fontSize:11,color:'#9ca3af',position:'relative'}}>NECROS X<div style={{position:'absolute',top:4,left:8,color:'#10b981'}}>●</div></div>
          <div><p style={{fontSize:13,color:'#9ca3af'}}>Model: NX-2000 (Raspberry Pi 5)</p><p style={{fontSize:13,color:'#9ca3af'}}>Firmware: v2.0.0</p></div>
          <div style={{textAlign:'right',flex:1}}><p style={{fontSize:13,color:'#9ca3af'}}>Uptime: {applMetrics.uptime}</p><p style={{fontSize:13,color:'#9ca3af'}}>Temp: {applMetrics.temperature}°C</p></div>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8,marginBottom:16}}>
          {[{l:'CPU',v:`${applMetrics.cpu.toFixed(0)}%`},{l:'Memory',v:`${applMetrics.mem.toFixed(0)}%`},{l:'Throughput',v:applMetrics.throughput},{l:'Packets',v:applMetrics.packets.toLocaleString()}].map(({l,v})=><div key={l} style={{background:'#1f2937',padding:8,borderRadius:4}}><div style={{fontSize:10,color:'#9ca3af'}}>{l}</div><div style={{fontSize:16,color:'#60a5fa'}}>{v}</div></div>)}
</div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
          <div><h4>GPIO Status</h4>
            <div style={{fontSize:13}}><span>DEFEND Button:</span><span style={{color:'#10b981'}}> ARMED (GPIO17)</span></div>
            <div style={{fontSize:13}}><span>Threat LED:</span><span style={{color:'#ef4444'}}> ACTIVE (GPIO22)</span></div>
            <div style={{fontSize:13}}><span>Heartbeat:</span><span style={{color:'#10b981'}}> ON (GPIO27)</span></div>
          </div>
          <div><h4>Live Packet Stream (Simulated)</h4>
            <div style={{background:'#111',height:150,overflowY:'auto',fontFamily:'monospace',fontSize:10,padding:4,borderRadius:4}}>
              {packets.map((p,i)=><div key={i} style={{display:'flex',justifyContent:'space-between',borderBottom:'1px solid #1f2937'}}><span>{p.time}</span><span style={{color:'#60a5fa'}}>{p.src}</span><span style={{color:'#fbbf24'}}>{p.method}</span><span>{p.path.slice(0,20)}</span><span style={{color:p.status===200?'#10b981':'#ef4444'}}>{p.status}</span></div>)}
            </div>
          </div>
        </div>
      </div>
      <p style={{fontSize:10,color:'#6b7280'}}>SIMULATED HARDWARE – Production uses real packet capture.</p>
    </div>
  );
}

/* ==================== Main App ==================== */
export default function App(){
  const [booted,setBooted]=useState(false);
  const [tab,setTab]=useState('dashboard');

  useEffect(()=>{
    const h=e=>{
      if(['s','S'].includes(e.key)) document.getElementById('scan-btn')?.click();
      if(['d','D'].includes(e.key)) document.getElementById('defend-btn')?.click();
      const tabs=['dashboard','registry','forecast','posture','attack','honeypot','intel','assistant','architecture','appliance'];
      const n=parseInt(e.key);
      if(n>=0&&n<=9) setTab(tabs[n]);
    };
    window.addEventListener('keydown',h);
    return ()=>window.removeEventListener('keydown',h);
  },[]);

  if(!booted) return <BootSequence onDone={()=>setBooted(true)}/>;

  const pages = {
    dashboard: <Dashboard/>, registry: <Registry/>, forecast: <Forecast/>, posture: <Posture/>,
    attack: <AttackPath/>, honeypot: <Honeypot/>, intel: <Intel/>, assistant: <AIAssistant/>,
    architecture: <Architecture/>, appliance: <ApplianceConsole/>
  };

  const {online,applMode,setApplMode,handleScan,handleDefend,notify} = useApp();

  return (
    <AppProvider>
      <NotificationToast/>
      <div style={{display:'flex',height:'100vh'}}>
        <div style={{width:240,background:'#111827',borderRight:'1px solid #374151',padding:'12px 8px',display:'flex',flexDirection:'column'}}>
          <div style={{fontSize:22,fontWeight:'bold',color:'#60a5fa',marginBottom:24,textShadow:'0 0 10px #3b82f6'}}>NECROS X</div>
          <nav style={{flex:1}}>
            {[['dashboard','Dashboard','1'],['registry','Registry','2'],['forecast','Forecast','3'],['posture','Posture','4'],['attack','Attack Path','5'],['honeypot','Honeypots','6'],['intel','Intel','7'],['assistant','AI Analyst','8'],['architecture','Architecture','9'],['appliance','Appliance','0']].map(([id,label,key])=><button key={id} onClick={()=>setTab(id)} style={{width:'100%',textAlign:'left',padding:'6px 10px',borderRadius:4,background:tab===id?'#1d4ed8':'transparent',color:tab===id?'white':'#d1d5db',border:'none',cursor:'pointer',marginBottom:2,fontSize:13}}><span style={{marginRight:6,fontSize:11,color:'#6b7280'}}>{key}</span>{label}</button>)}
          </nav>
          {!online&&<div style={{color:'#ef4444',fontSize:11}}>OFFLINE MODE</div>}
          <div style={{margin:'12px 0',display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <span style={{fontSize:11,color:'#9ca3af'}}>Appliance Mode</span>
            <button onClick={()=>setApplMode(!applMode)} style={{width:40,height:20,borderRadius:10,background:applMode?'#2563eb':'#4b5563',border:'none',cursor:'pointer',position:'relative'}}><span style={{position:'absolute',left:2,top:2,width:16,height:16,borderRadius:'50%',background:'white',transition:'transform 0.2s',transform:applMode?'translateX(20px)':'translateX(0)'}}/></button>
          </div>
          <Terminal onCmd={c=>{ if(c==='scan')handleScan('https://api.examplebank.com'); else if(c==='defend')handleDefend(); else notify('Unknown command','error'); }}/>
        </div>
        <div style={{flex:1,overflow:'auto',padding:16}}>
          {pages[tab]}
        </div>
      </div>
    </AppProvider>
  );
}
```

---


