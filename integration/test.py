import hashlib,http.cookiejar,json,os,secrets,socket,subprocess,tempfile,time
from pathlib import Path
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.request import Request,build_opener,HTTPCookieProcessor,urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError
REPO=Path(__file__).resolve().parents[1];SHARED=REPO/"integration/privacy-lib"
paths={"node":os.environ.get("NODE_BINARY","node"),"node22":os.environ.get("NODE_BINARY","node")}
files=[SHARED/"gdpr-router.cjs",*sorted((SHARED/"gdpr").glob("*.rego"))]
hashes=lambda:[hashlib.sha256(p.read_bytes()).hexdigest() for p in files]
before=hashes();checks=[]
def check(label,value):
    assert value,label
    checks.append({"name":label,"passed":True});print("PASS",label,flush=True)
def port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]
def client():return build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
class Form(HTMLParser):
    token=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=="meta" and a.get("name")=="csrf-token":self.token=a.get("content")
        if tag=="input" and a.get("name")=="_csrf":self.token=a.get("value")
opa_port,app_port=port(),port();base=f"http://localhost:{app_port}"
email=f"privacy-alice-{int(time.time())}@example.org";other_email=f"privacy-bob-{int(time.time())}@example.org"
env=dict(os.environ,PORT=str(app_port),BASE_URL=base,GDPR_ADMIN_EMAILS=email,SESSION_SECRET=secrets.token_hex(32),
 OPA_QUERY_URL=f"http://127.0.0.1:{opa_port}/v1/query",MONGOMS_VERSION="7.0.24",
 NODE_ENV="development")
env.pop("MONGODB_URI",None)
flags=getattr(subprocess,"CREATE_NO_WINDOW",0)
opa=subprocess.Popen([os.environ.get("OPA_BINARY","opa"),"run","--server","--addr",f"127.0.0.1:{opa_port}",str(SHARED/"gdpr")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=flags)
def html(c,route):
    with c.open(base+route,timeout=15) as r:return r.geturl(),r.read().decode()
def csrf(c):
    _,text=html(c,"/");p=Form();p.feed(text);assert p.token;return p.token
def form(c,route,body):
    body=dict(body,_csrf=csrf(c))
    with c.open(Request(base+route,data=urlencode(body).encode()),timeout=20) as r:return r.geturl(),r.read().decode()
def api(c,policy,body=None,method="POST",token=True):
    headers={"Content-Type":"application/json"}
    if token:headers["X-CSRF-Token"]=csrf(c)
    try:
        with c.open(Request(base+"/gdpr/"+policy,data=json.dumps(body or {}).encode(),headers=headers,method=method),timeout=15) as r:
            return r.status,json.loads(r.read())
    except HTTPError as e:
        raw=e.read().decode()
        try:data=json.loads(raw)
        except ValueError:data=raw
        return e.code,data
with tempfile.TemporaryFile() as log:
    app=subprocess.Popen([paths["node"],"test/tools/start-with-memory-db.js"],cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT,creationflags=flags)
    try:
        alice,bob=client(),client()
        for _ in range(200):
            if app.poll() is not None:log.seek(0);raise RuntimeError(log.read().decode())
            try:html(alice,"/");break
            except OSError:time.sleep(.2)
        else:log.seek(0);raise RuntimeError("Startup timeout\n"+log.read().decode())
        for _ in range(100):
            try:
                with urlopen(f"http://127.0.0.1:{opa_port}/health",timeout=1):break
            except OSError:time.sleep(.1)
        check("Unauthenticated evaluation denied",api(alice,"consent")[0]==401)
        form(alice,"/signup",{"email":email,"password":"Integration123","confirmPassword":"Integration123"})
        check("Original signup and session",html(alice,"/account")[0].endswith("/account"))
        html(alice,"/logout")
        form(alice,"/login",{"email":email,"password":"Integration123"})
        check("Original password login works",email in html(alice,"/account")[1])
        form(alice,"/account/profile",{"email":email,"name":"Alice Private Profile","gender":"other","location":"Alice Private City","website":"https://example.org/alice"})
        check("Original profile update works","Alice Private Profile" in html(alice,"/account")[1])
        check("Authenticated privacy page renders","Privacy checks" in html(alice,"/gdpr")[1])
        check("CSRF cannot be omitted",api(alice,"consent",token=False)[0]==403)
        check("Missing consent denies processing",api(alice,"consent")==(200,False))
        check("Consent stored",api(alice,"consent",{"value":"yes","withdrawn":False},"PATCH")== (200,{"value":"yes","withdrawn":False}))
        for policy in ["consent","lawful"]:check(policy+" accepts stored consent",api(alice,policy)==(200,True))
        status,data=api(alice,"information");check("Information reports consent and lawfulness",status==200 and data["consent_valid"] and data["lawful_processing"])
        status,data=api(alice,"access");download=json.loads(data["download"]["content"]);subject=download["user_id"]
        check("Access maps actual profile fields",status==200 and sorted(x["field"] for x in download["data_collected_from_user"])==["email","gender","location","name","website"])
        check("Access excludes password and tokens",all(key not in json.dumps(data) for key in ['"password"','"tokens"','"totpSecret"','"webauthnCredentials"']))
        status,data=api(alice,"rectification",{"updates":{"name":"Updated Alice"}})
        check("Rectification plan targets authenticated user",status==200 and data["request"]["validated"] and any(x["user_id"]==subject and x["new_value"]=="Updated Alice" for x in data["db_update_plan"]))
        status,data=api(alice,"erasure",{"fields":["email"]});check("Email retention exception enforced",status==200 and data["decision"]=="reject" and "delete" not in data["actions"])
        status,data=api(alice,"restriction");check("Restriction produces plan",status==200 and data["decision"]=="accept")
        status,data=api(alice,"portability")
        check("Portability returns JSON/CSV and profile values",status==200 and data["decision"]=="accept" and len(data["actions"]["downloads"])==2 and "Alice Private Profile" in json.dumps(data) and "Alice Private City" in json.dumps(data) and email in json.dumps(data))
        check("Portability excludes credentials",all(key not in json.dumps(data) for key in ['"password"','"tokens"','"totpSecret"','"webauthnCredentials"']))
        status,data=api(alice,"objection",{"reason":"marketing"});check("Objection stop plan",status==200 and data["decision"]=="accept")
        status,data=api(alice,"complaint",{"authority_id":"cy-0000","description":"Integration test only; do not send"});check("Complaint forward plan",status==200 and data["decision"]=="accept")
        status,data=api(alice,"breach",{"incident_id":"test-incident"});check("Explicitly configured administrator can assess breach",status==200 and data["decision"]=="notify_users")
        form(bob,"/signup",{"email":other_email,"password":"Integration456","confirmPassword":"Integration456"})
        form(bob,"/account/profile",{"email":other_email,"name":"Bob Private Profile","gender":"other","location":"Bob Private City","website":"https://example.org/bob"})
        check("Independent second user has no inherited consent",api(bob,"consent")==(200,False))
        check("Normal user cannot assess breach",api(bob,"breach",{"incident_id":"x"})[0]==403)
        assert api(bob,"consent",{"value":"yes","withdrawn":False},"PATCH")[0]==200
        status,data=api(bob,"portability")
        check("Bob export excludes Alice profile",status==200 and "Bob Private Profile" in json.dumps(data) and "Alice Private Profile" not in json.dumps(data) and email not in json.dumps(data))
        status,data=api(alice,"portability")
        check("Alice export excludes Bob profile","Alice Private Profile" in json.dumps(data) and "Bob Private Profile" not in json.dumps(data))
        check("Cannot supply another user's identity",api(bob,"access",{"user_id":subject})[0]==400)
        check("Unknown operation is rejected",api(alice,"unknown")[0]==400)
        check("Invalid consent value is rejected",api(alice,"consent",{"value":"yes","withdrawn":"false"},"PATCH")[0]==400)
        check("Consent withdrawal stored",api(alice,"consent",{"value":"yes","withdrawn":True},"PATCH")[0]==200)
        for policy in ["consent","lawful","portability"]:
            status,data=api(alice,policy);check(policy+" denies after withdrawal",status==200 and (data["decision"]=="reject" if isinstance(data,dict) else data is False))
        status,data=api(alice,"access");check("Access remains available after withdrawal",status==200 and data["request"]["validated"])
        status,data=api(alice,"erasure",{"fields":["name"],"reason":"withdrawn_consent"});check("Eligible erasure returns delete plan",status==200 and data["decision"]=="accept")
        check("Decision plans do not mutate profile","Alice Private Profile" in html(alice,"/account")[1])
        opa.terminate();opa.wait(timeout=10);check("OPA outage returns 502",api(alice,"consent")[0]==502)
        check("Shared router/policies unchanged",hashes()==before)
        result={"repository":"sahat/hackathon-starter","commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip(),
         "timestamp":datetime.now(timezone.utc).isoformat(),"passed":len(checks),"checks":checks,
         "policies":["consent","lawful","information","access","rectification","erasure","restriction","portability","objection","complaint","breach"],
         "limitations":["Plans only; no database edits/deletions or messages executed","Access returns field metadata only","Synthetic business/policy metadata","Selected profile fields mapped; credentials and provider tokens excluded","Breach administrator uses explicit integration email allowlist; upstream has no admin role"]}
        subprocess.run([paths["node"],str(REPO/"integration/test-support.cjs"),"record"],input=json.dumps(result),text=True,check=True)
        print("Integration result:",len(checks),"/",len(checks),"passed",flush=True)
    finally:
        app.terminate();app.wait(timeout=15)
        if opa.poll() is None:opa.terminate();opa.wait(timeout=10)
