import os,sys,json,time,hashlib,shutil,subprocess
from pathlib import Path
import httpx
SERVER=os.getenv("FORENSIC_SERVER","").rstrip("/")
KEY=os.getenv("CASE_API_KEY","")
OUT=Path(os.getenv("FORENSIC_AGENT_OUTPUT","agent_output"));OUT.mkdir(exist_ok=True)
def run(*a):
 p=subprocess.run(["adb",*a],capture_output=True,text=True);return p.returncode,p.stdout.strip(),p.stderr.strip()
def sh(c):return run("shell",c)
def prop(n):return sh("getprop "+n)[1]
def devs():
 r,o,e=run("devices");return [x.split("\\t")[0] for x in o.splitlines()[1:] if "\\tdevice" in x]
def lines(c):
 r,o,e=sh(c)
 if r:return []
 return [x for x in o.splitlines() if x.strip()]
def query(uri,proj):
 r,o,e=sh(f"content query --uri {uri} --projection {proj}")
 if r: raise RuntimeError(e or "query failed")
 return [x for x in o.splitlines() if "Row:" in x]
def sha(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for b in iter(lambda:f.read(1048576),b):h.update(b)
 return h.hexdigest()
def apk(pkg):
 r,o,e=sh("pm path "+pkg);paths=[x.replace("package:","").strip() for x in o.splitlines() if x.startswith("package:")]
 if not paths:return None
 p=OUT/"apk_cache"/(pkg.replace(".","_")+".apk");p.parent.mkdir(exist_ok=True)
 q=subprocess.run(["adb","pull",paths[0],str(p)],capture_output=True)
 return sha(p) if q.returncode==0 and p.exists() else None
def collect(device):
 errors=[]
 def q(fn,default=[]):
  try:return fn()
  except Exception as e:errors.append(str(e));return default
 contacts=q(lambda:query("content://com.android.contacts/data","display_name:data1:mimetype"))
 sms=q(lambda:query("content://sms","_id:address:date:type:body"))
 packages=q(lambda:[x.replace("package:","").strip() for x in lines("pm list packages -3") if x.startswith("package:")])
 running=q(lambda:lines("ps -A"))
 access=q(lambda:lines("settings get secure enabled_accessibility_services"))
 admins=q(lambda:lines("dumpsys device_policy | grep -i 'admin='"))
 network=q(lambda:lines("cat /proc/net/tcp"))
 terms=("spy","stealer","keylog","rat","inject","payload","trojan","stalker","remoteadmin")
 flags=[p for p in packages if any(t in p.lower() for t in terms)]
 findings=[]
 if flags:findings.append({"category":"Application triage","severity":"warning","message":"Package-name heuristic match; validate signature, provenance and APK hash.","packages":flags})
 if access and access!=["null"]:findings.append({"category":"Accessibility","severity":"review","message":"Enabled accessibility services should be reviewed for legitimate purpose.","services":access})
 if admins:findings.append({"category":"Device administration","severity":"review","message":"Device-admin entries should be reviewed.","records":admins})
 hashes={}
 for p in packages:
  try:
   h=apk(p)
   if h:hashes[p]=h
  except Exception as e:errors.append(f"APK {p}: {e}")
 return {"device_id":device,"agent_version":"2.0.0","device":{
 "manufacturer":prop("ro.product.manufacturer"),"model":prop("ro.product.model"),
 "android":prop("ro.build.version.release"),"sdk":prop("ro.build.version.sdk"),
 "security_patch":prop("ro.build.version.security_patch"),"fingerprint":prop("ro.build.fingerprint"),
 "selinux":sh("getenforce")[1],"verified_boot":prop("ro.boot.verifiedbootstate"),
 "encryption":prop("ro.crypto.state"),"adb_authentication":prop("ro.adb.secure")},
 "contacts":contacts,"sms":sms,"packages":packages,"suspicious_package_flags":flags,
 "running_processes":running,"accessibility_services":access,"device_admins":admins,
 "network_connections":network,"apk_hashes":hashes,"findings":findings,"errors":errors}
def main():
 if not shutil.which("adb"):raise SystemExit("adb not found in PATH")
 if not SERVER:raise SystemExit("Set FORENSIC_SERVER")
 ds=devs()
 if not ds:raise SystemExit("No authorized device. Run adb devices.")
 e=collect(ds[0]);local=OUT/("scan_"+time.strftime("%Y%m%d_%H%M%S")+".json");local.write_text(json.dumps(e,indent=2),encoding="utf-8")
 h={"Content-Type":"application/json"} 
 if KEY:h["X-API-Key"]=KEY
 r=httpx.post(SERVER+"/api/scans",json=e,headers=h,timeout=180);r.raise_for_status()
 print("Uploaded:",r.json());print("Contacts:",len(e["contacts"]),"SMS:",len(e["sms"]),"Apps:",len(e["packages"]),"Running:",len(e["running_processes"]),"Flags:",len(e["suspicious_package_flags"]))
if __name__=="__main__":main()
