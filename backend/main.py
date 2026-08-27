import os,json,sqlite3,secrets
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI,Header,HTTPException
from fastapi.responses import HTMLResponse,JSONResponse
from pydantic import BaseModel,Field

ROOT=Path(__file__).resolve().parent.parent
DB=Path(os.getenv("FORENSIC_DB",str(ROOT/"data"/"forensic.db")))
UI=ROOT/"frontend"/"index.html"
KEY=os.getenv("CASE_API_KEY","").strip()
DB.parent.mkdir(parents=True,exist_ok=True)

app=FastAPI(title="Smart Cyber Forensic Pro",version="2.0.0")

def now(): return datetime.now(timezone.utc).isoformat()
def db():
    c=sqlite3.connect(DB,timeout=30); c.row_factory=sqlite3.Row; return c
def init():
    c=db(); c.execute("""CREATE TABLE IF NOT EXISTS scans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT UNIQUE,created_at TEXT,
      device_id TEXT,manufacturer TEXT,model TEXT,android TEXT,sdk TEXT,
      security_patch TEXT,selinux TEXT,verified_boot TEXT,encryption TEXT,
      contacts_count INTEGER DEFAULT 0,sms_count INTEGER DEFAULT 0,
      packages_count INTEGER DEFAULT 0,running_count INTEGER DEFAULT 0,
      accessibility_count INTEGER DEFAULT 0,admin_count INTEGER DEFAULT 0,
      network_count INTEGER DEFAULT 0,suspicious_count INTEGER DEFAULT 0,
      evidence_json TEXT NOT NULL)"""); c.commit(); c.close()
init()

def auth(k):
    if KEY and k!=KEY: raise HTTPException(401,"Invalid API key")

class Evidence(BaseModel):
    device_id:str=Field(min_length=1,max_length=512)
    case_id:str|None=None
    device:dict[str,Any]={}
    contacts:list[Any]=[]
    sms:list[Any]=[]
    packages:list[Any]=[]
    suspicious_package_flags:list[Any]=[]
    running_processes:list[Any]=[]
    accessibility_services:list[Any]=[]
    device_admins:list[Any]=[]
    network_connections:list[Any]=[]
    apk_hashes:dict[str,str]={}
    findings:list[Any]=[]
    errors:list[str]=[]
    agent_version:str="unknown"

@app.get("/",response_class=HTMLResponse)
def home(): return UI.read_text(encoding="utf-8") if UI.exists() else "<h1>Smart Cyber Forensic Pro</h1><a href='/docs'>API docs</a>"

@app.get("/health")
def health(): return {"status":"ok","time":now()}

@app.get("/api/stats")
def stats():
    c=db(); r=c.execute("""SELECT COUNT(*) scans,COALESCE(SUM(contacts_count),0) contacts,
    COALESCE(SUM(sms_count),0) sms,COALESCE(SUM(packages_count),0) applications,
    COALESCE(SUM(running_count),0) running,COALESCE(SUM(suspicious_count),0) suspicious FROM scans""").fetchone()
    c.close(); return dict(r)

@app.post("/api/scans")
def upload(e:Evidence,x_api_key:str|None=Header(None,alias="X-API-Key")):
    auth(x_api_key)
    case=e.case_id or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3).upper()}"
    d=e.device; c=db()
    try:
        cur=c.execute("""INSERT INTO scans(case_id,created_at,device_id,manufacturer,model,android,sdk,
        security_patch,selinux,verified_boot,encryption,contacts_count,sms_count,packages_count,
        running_count,accessibility_count,admin_count,network_count,suspicious_count,evidence_json)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(case,now(),e.device_id,d.get("manufacturer"),d.get("model"),
        d.get("android"),d.get("sdk"),d.get("security_patch"),d.get("selinux"),d.get("verified_boot"),
        d.get("encryption"),len(e.contacts),len(e.sms),len(e.packages),len(e.running_processes),
        len(e.accessibility_services),len(e.device_admins),len(e.network_connections),
        len(e.suspicious_package_flags),e.model_dump_json()))
        c.commit()
    except sqlite3.IntegrityError:
        c.close(); raise HTTPException(409,"Case ID already exists")
    sid=cur.lastrowid;c.close()
    return {"status":"stored","scan_id":sid,"case_id":case}

@app.get("/api/scans")
def list_scans():
    c=db(); rows=c.execute("""SELECT id,case_id,created_at,device_id,manufacturer,model,android,
    security_patch,contacts_count,sms_count,packages_count,running_count,accessibility_count,
    admin_count,network_count,suspicious_count FROM scans ORDER BY id DESC""").fetchall();c.close()
    return [dict(x) for x in rows]

def get(sid):
    c=db(); r=c.execute("SELECT * FROM scans WHERE id=?",(sid,)).fetchone();c.close()
    if not r: raise HTTPException(404,"Scan not found")
    x=dict(r); raw=x.pop("evidence_json")
    try:x["evidence"]=json.loads(raw)
    except Exception:x["evidence"]={}
    return x

@app.get("/api/scans/{sid}")
def scan(sid:int): return get(sid)
@app.get("/api/scans/{sid}/contacts")
def contacts(sid:int):
    e=get(sid)["evidence"]; return {"count":len(e.get("contacts",[])),"contacts":e.get("contacts",[])}
@app.get("/api/scans/{sid}/sms")
def sms(sid:int):
    e=get(sid)["evidence"]; return {"count":len(e.get("sms",[])),"sms":e.get("sms",[])}
@app.get("/api/scans/{sid}/applications")
def apps(sid:int):
    e=get(sid)["evidence"]; return {"count":len(e.get("packages",[])),"applications":e.get("packages",[]),"suspicious":e.get("suspicious_package_flags",[])}
@app.get("/api/scans/{sid}/analysis")
def analysis(sid:int):
    e=get(sid)["evidence"]; return {k:e.get(k,[]) for k in ["device","running_processes","accessibility_services","device_admins","network_connections","findings","errors"]}
@app.get("/api/scans/{sid}/hashes")
def hashes(sid:int):
    e=get(sid)["evidence"]; return {"sha256":e.get("apk_hashes",{})}
@app.get("/api/scans/{sid}/export")
def export(sid:int):
    return JSONResponse(get(sid),headers={"Content-Disposition":f'attachment; filename="forensic_case_{sid}.json"'})
