import base64
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser, Parser
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

MAX_MESSAGE_LENGTH = 1_000_000
PORT = 8000
RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1",
    ".js", ".jse", ".vbs", ".vbe", ".hta", ".msi", ".msp", ".iso",
    ".img", ".lnk", ".url", ".chm", ".jar", ".docm", ".xlsm", ".pptm",
    ".zip", ".rar", ".7z"
}
URL_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy", "cutt.ly"}

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mail Check | Email Security Analysis</title>
<style>
:root{color-scheme:light;--ink:#172a2b;--muted:#657475;--line:#d8e2df;--paper:#f2f6f4;--panel:#fff;--green:#176b55;--red:#a53d35;--amber:#8b5c13}
*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:var(--paper);background-image:radial-gradient(#cbd8d3 .7px,transparent .7px);background-size:18px 18px;font:15px/1.55 "Segoe UI",sans-serif}
header{padding:28px 22px 22px;border-bottom:1px solid var(--line);background:#f8faf9ef}.top,main{width:min(100% - 32px,1120px);margin:auto}
.eyebrow{margin:0 0 7px;color:var(--green);font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase}h1{margin:0;font:400 clamp(30px,5vw,44px)/1.08 Georgia,serif}.intro{max-width:760px;margin:12px 0 0;color:var(--muted)}
main{padding:26px 0 54px}.workspace{display:grid;grid-template-columns:minmax(0,.85fr) minmax(0,1.15fr);gap:18px;align-items:start}.panel{border:1px solid var(--line);border-radius:8px;background:var(--panel);box-shadow:0 8px 22px #1c39310b}.input-panel,.results{padding:20px}.section-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:13px}h2{margin:0;font-size:16px}
.upload{color:var(--green);font-size:13px;font-weight:650;cursor:pointer}.upload input{position:absolute;width:1px;height:1px;opacity:0}
textarea{display:block;width:100%;min-height:330px;resize:vertical;padding:13px;border:1px solid var(--line);border-radius:5px;color:var(--ink);background:#fbfcfc;font:13px/1.5 Consolas,monospace}textarea:focus{outline:2px solid #176b5540;border-color:var(--green)}
.actions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:13px;flex-wrap:wrap}.hint,.fineprint{color:var(--muted);font-size:12px}button{padding:10px 15px;border:0;border-radius:4px;color:white;background:var(--green);font:650 13px "Segoe UI",sans-serif;cursor:pointer}button:hover{background:#105641}button:disabled{opacity:.65;cursor:wait}.secondary{background:#e8efec;color:var(--ink)}.secondary:hover{background:#dce7e2}
.results{min-height:200px}.empty{color:var(--muted)}.verdict{display:flex;justify-content:space-between;gap:12px;align-items:baseline;padding-bottom:14px;border-bottom:1px solid var(--line)}.verdict h2{font:400 25px/1.2 Georgia,serif}.verdict.high h2{color:var(--red)}.verdict.review h2{color:var(--amber)}.verdict.clear h2{color:var(--green)}.score{color:var(--muted);font:12px Consolas,monospace}.summary{color:var(--muted)}
.subhead{margin:21px 0 8px;font-size:12px;letter-spacing:.7px;text-transform:uppercase}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.tile{padding:10px;border-radius:5px;background:#f4f7f6;min-width:0}.tile b{display:block;font-size:12px;color:var(--muted);margin-bottom:3px}.tile span{overflow-wrap:anywhere}.auth-list,.finding-list,.data-list{display:grid;gap:7px;margin:0;padding:0;list-style:none}.auth-row,.finding,.data-row{display:block;padding:9px 10px;border-radius:4px;background:#f4f7f6;font-size:13px;overflow-wrap:anywhere}.auth-row{display:flex;justify-content:space-between;gap:12px}.status{font:700 11px Consolas,monospace;text-transform:uppercase}.pass{color:var(--green)}.fail{color:var(--red)}.unknown{color:var(--muted)}.finding{border-left:3px solid #d2a64c}.finding.high{border-color:var(--red)}.finding b{display:block;margin-bottom:2px}.data-row small{display:block;color:var(--muted);overflow-wrap:anywhere}.pill{display:inline-block;margin:3px 5px 0 0;padding:2px 7px;border-radius:12px;background:#e7eeeb;font-size:11px}.pill.bad{background:#f7e5e2;color:var(--red)}details{margin-top:8px;border:1px solid var(--line);border-radius:5px;padding:9px 11px}summary{cursor:pointer;font-weight:650;font-size:13px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:340px;overflow:auto;font:12px/1.5 Consolas,monospace}.fineprint{margin:18px 0 0;padding-top:13px;border-top:1px solid var(--line)}.error{color:var(--red)}.empty-state{padding:16px;background:#f4f7f6;border-radius:5px;color:var(--muted);font-size:13px}
.vt-config{display:grid;gap:7px;margin-top:16px}.vt-config label{font-size:13px;font-weight:650}.vt-config input{width:100%;padding:11px;border:1px solid var(--line);border-radius:5px;font:inherit}.vt-panel{padding:12px;background:#f7faf9;border:1px solid var(--line);border-radius:7px}.vt-card{display:grid;gap:7px;padding:12px;margin:8px 0;background:#fff;border:1px solid var(--line);border-radius:5px}.vt-card p{margin:0;overflow-wrap:anywhere}.pill.good{background:#e3f3ea;color:#176b55}.vt-results{overflow-wrap:anywhere}.vt-results a{font-size:13px}@media(max-width:820px){.workspace{grid-template-columns:1fr}}@media(max-width:500px){.grid{grid-template-columns:1fr}.verdict{align-items:flex-start;flex-direction:column}header{padding-top:22px}}
</style></head>
<body><header><div class="top"><p class="eyebrow">Local email analysis</p><h1>Mail Check</h1><p class="intro">Inspect raw email headers, authentication results, message body, URLs, attachments, and indicators of compromise. Analysis runs on this computer.</p></div></header>
<main><div class="workspace">
<section class="panel input-panel" aria-labelledby="input-title"><div class="section-head"><h2 id="input-title">Email source</h2><label class="upload">Open .eml<input id="file" type="file" accept=".eml,message/rfc822,text/plain"></label></div>
<textarea id="email" placeholder="Paste the full raw email, including headers, here..." spellcheck="false"></textarea>
<div class="actions"><span class="hint">Local only · Maximum 1 MB</span><button id="analyze">Analyze email</button></div>
<div class="vt-config"><label for="vt-key">VirusTotal API key</label><input id="vt-key" type="password" autocomplete="off" placeholder="VirusTotal API key (session only)">
<label for="abuse-key">AbuseIPDB API key</label><input id="abuse-key" type="password" autocomplete="off" placeholder="AbuseIPDB API key (session only)">
<label for="urlhaus-key">URLhaus Auth-Key</label><input id="urlhaus-key" type="password" autocomplete="off" placeholder="URLhaus Auth-Key (if required by your account)">
<label for="phishtank-key">PhishTank API key (optional)</label><input id="phishtank-key" type="password" autocomplete="off" placeholder="PhishTank app_key (optional)">
<label for="otx-key">AlienVault OTX API key</label><input id="otx-key" type="password" autocomplete="off" placeholder="OTX API key (session only)">
<span class="hint">Keys stay in this page session and are sent only to the local app, which forwards requests to the selected provider. Each service runs independently. URLhaus may require an Auth-Key depending on current API access.</span></div>
</section>
<section id="results" class="panel results" aria-live="polite"><p class="empty">Your analysis will appear here.</p></section>
</div></main>
<script>
const input=document.querySelector('#email'),results=document.querySelector('#results'),button=document.querySelector('#analyze');
let lastReport=null;
document.querySelector('#file').addEventListener('change',async e=>{const f=e.target.files[0];if(f){if(f.size>1000000){showError('File exceeds the 1 MB limit.');return}input.value=await f.text()}});
function el(parent,tag,text='',cls=''){const n=document.createElement(tag);if(cls)n.className=cls;n.textContent=text;parent.append(n);return n}
function section(parent,title){el(parent,'h3',title,'subhead')}
function empty(parent,text){el(parent,'div',text,'empty-state')}
function renderRows(parent,items,formatter){if(!items||!items.length){empty(parent,'None found.');return}const ul=el(parent,'ul','','data-list');for(const item of items){const li=el(ul,'li','','data-row');formatter(li,item)}}
function showError(message){results.replaceChildren();el(results,'p',message,'error')}
function show(d){
 lastReport=d;results.replaceChildren();
 const top=el(results,'div','','verdict '+d.level);el(top,'h2',d.verdict);el(top,'span','Risk score '+d.score,'score');
 el(results,'p',d.summary,'summary');
 section(results,'Email overview');const grid=el(results,'div','','grid');
 for(const [label,value] of Object.entries(d.headers)){const tile=el(grid,'div','','tile');el(tile,'b',label);el(tile,'span',value||'Not present')}
 section(results,'Authentication headers (SPF / DKIM / DMARC / ARC)');const auth=el(results,'ul','','auth-list');
 const authHeaderNames={'SPF':['Received-SPF','Authentication-Results'],'DKIM':['DKIM-Signature','Authentication-Results'],'DMARC':['Authentication-Results'],'ARC':['ARC-Authentication-Results','ARC-Seal']};
 for(const a of d.authentication){
   const row=el(auth,'li','','auth-row');
   el(row,'span',a.name);
   const headerPresent=(authHeaderNames[a.name]||[]).some(h=>Object.keys(d.raw_header_presence||{}).some(k=>k.toLowerCase()===h.toLowerCase()&&d.raw_header_presence[k]));
   const detail=el(row,'span',(headerPresent?'HEADER FOUND':'HEADER NOT FOUND')+' · '+a.status,(headerPresent?'status unknown':'status fail'));
 }
 el(results,'p','Header presence and authentication results are separate checks. Values are reported by the email headers and are not independently verified.','hint');
 section(results,'Important headers found / missing');const hp=el(results,'div','','grid');
 for(const [name,present] of Object.entries(d.raw_header_presence||{})){const tile=el(hp,'div','','tile');el(tile,'b',name);el(tile,'span',present?'Found in message':'Not found in message',present?'status pass':'status unknown')}
 section(results,'Findings');const fl=el(results,'ul','','finding-list');
 if(d.findings.length){for(const f of d.findings){const li=el(fl,'li','','finding '+f.severity);el(li,'b',f.title||'Signal');el(li,'span',f.text)}}else{el(fl,'li','No common warning signals were found.','finding')}
 section(results,'URLs and links ('+d.links.length+')');
 renderRows(results,d.links,(li,x)=>{
   const safeUrl=/^https?:\/\//i.test(x.url||'');
   if(safeUrl){const a=el(li,'a',x.url);a.href=x.url;a.target='_blank';a.rel='noopener noreferrer';a.referrerPolicy='no-referrer';}
   else {el(li,'b',x.url||'[empty URL]');}
   if(x.text)el(li,'small','Visible text: '+x.text);
   el(li,'small','Host: '+(x.host||'unknown')+' · '+x.reason);
 });
 section(results,'Attachments ('+d.attachments.length+')');
 renderRows(results,d.attachments,(li,x)=>{el(li,'b',x.filename||'[unnamed attachment]');el(li,'small','MIME: '+x.content_type+' · Size: '+x.size_bytes+' bytes');el(li,'small','SHA-256: '+x.sha256);if(x.risky)el(li,'span','Potentially risky file type','pill bad');if(x.extension_mismatch)el(li,'span','Extension/MIME mismatch — review','pill bad')});
 const providers=[
   {id:'virustotal',title:'VirusTotal',key:'vt-key',description:'Checks existing reports for URLs and attachment SHA-256 hashes.',payload:()=>({api_key:document.querySelector('#vt-key').value.trim(),links:d.links.map(x=>x.url),hashes:d.attachments.map(x=>x.sha256)})},
   {id:'abuseipdb',title:'AbuseIPDB',key:'abuse-key',description:'Checks the reputation and abuse reports for extracted IPv4 addresses.',payload:()=>({api_key:document.querySelector('#abuse-key').value.trim(),ips:d.iocs['IPv4 addresses']||[]})},
   {id:'urlhaus',title:'URLhaus',key:'urlhaus-key',description:'Checks extracted URLs against malware-distribution URLhaus records.',payload:()=>({api_key:document.querySelector('#urlhaus-key').value.trim(),links:d.links.map(x=>x.url)})},
   {id:'phishtank',title:'PhishTank',key:'phishtank-key',description:'Checks whether extracted URLs are listed as reported phishing URLs.',payload:()=>({api_key:document.querySelector('#phishtank-key').value.trim(),links:d.links.map(x=>x.url)})},
   {id:'otx',title:'AlienVault OTX',key:'otx-key',description:'Checks extracted IPs, domains and attachment SHA-256 hashes against OTX.',payload:()=>({api_key:document.querySelector('#otx-key').value.trim(),ips:d.iocs['IPv4 addresses']||[],domains:d.iocs['Domains']||[],hashes:d.attachments.map(x=>x.sha256)})}
 ];
 for(const provider of providers){
   section(results,provider.title+' Threat Intelligence check');
   const box=el(results,'div','','vt-panel');el(box,'p',provider.description,'hint');
   const actions=el(box,'div','','actions');const btn=el(actions,'button','Check '+provider.title,'secondary');btn.type='button';
   const status=el(box,'div','','vt-results');
   btn.addEventListener('click',async()=>{
     const payload=provider.payload();
     if(provider.id!=='urlhaus' && !payload.api_key){status.replaceChildren();el(status,'p','Enter the '+provider.title+' API key above first.','error');return}
     btn.disabled=true;btn.textContent='Checking…';status.replaceChildren();el(status,'p','Querying '+provider.title+' reputation data…','hint');
     try{
       const resp=await fetch('/threatintel/'+provider.id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
       const data=await resp.json();status.replaceChildren();
       if(!resp.ok||data.error){el(status,'p',data.error||provider.title+' lookup failed.','error')}
       else{
         el(status,'p',data.note||'Lookup complete.','hint');
         if(!data.results||!data.results.length)empty(status,'No indicators were available to check.');
         else for(const item of data.results){
           const card=el(status,'div','','vt-card');el(card,'b',item.indicator||'Indicator');
           el(card,'span',(item.kind||provider.title)+' · '+(item.status||'Checked'),'pill '+(/malicious|phishing|listed|abusive|high risk|blacklisted/i.test(item.status||'')?'bad':/not found|no report|clean|not listed|no detections/i.test(item.status||'')?'good':''));
           if(item.summary)el(card,'p',item.summary);
           if(item.message)el(card,'p',item.message,'hint');
           if(item.url){const a=el(card,'a','Open provider report');a.href=item.url;a.target='_blank';a.rel='noopener noreferrer';a.referrerPolicy='no-referrer'}
         }
       }
     }catch(e){status.replaceChildren();el(status,'p','Could not reach the local '+provider.title+' endpoint. Is the app running?','error')}
     finally{btn.disabled=false;btn.textContent='Check '+provider.title}
   });
 }
 section(results,'Indicators of compromise (IOCs)');const ioc=el(results,'div','','grid');
 for(const [label,values] of Object.entries(d.iocs)){const tile=el(ioc,'div','','tile');el(tile,'b',label);el(tile,'span',values.length?values.join(', '):'None found')}
 section(results,'Email body');
 const body=el(results,'details');const sum=el(body,'summary','View extracted plain-text body');const pre=el(body,'pre',d.body.text||'[No readable text body found.]');
 const html=el(results,'details');el(html,'summary','View HTML body as inert source');el(html,'pre',d.body.html||'[No HTML body found.]');
 const raw=el(results,'details');el(raw,'summary','View selected raw headers');el(raw,'pre',d.raw_headers||'[No headers found.]');
 const actions=el(results,'div','','actions');const exportBtn=el(actions,'button','Download JSON report','secondary');exportBtn.type='button';exportBtn.addEventListener('click',()=>{const blob=new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='mail-check-report.json';a.click();URL.revokeObjectURL(url)});
 el(results,'p','Screening aid only. Do not open suspicious attachments or visit suspicious links. Header values may be forged; confirm sensitive requests through a separate trusted channel. External reputation checks are optional and each provider can fail independently.','fineprint');
}
button.addEventListener('click',async()=>{if(!input.value.trim()){showError('Paste an email message before analyzing.');return}button.disabled=true;button.textContent='Checking...';try{const r=await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:input.value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not analyze this message.');show(d)}catch(e){showError(e.message)}finally{button.disabled=false;button.textContent='Analyze email'}});
</script></body></html>"""


class MessageText(HTMLParser):
    """Extract readable HTML text and anchor links without rendering the HTML."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.current_link = None
        self.hidden_elements = []
        self.forms = 0
        self.script_tags = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            self.current_link = {"url": attrs.get("href", ""), "text": []}
        if tag == "form":
            self.forms += 1
        if tag == "script":
            self.script_tags += 1
        style = (attrs.get("style") or "").lower().replace(" ", "")
        if attrs.get("hidden") is not None or attrs.get("aria-hidden", "").lower() == "true" or "display:none" in style or "visibility:hidden" in style:
            self.hidden_elements.append(tag)
        if tag == "input" and (attrs.get("type") or "").lower() in {"password", "email"}:
            self.hidden_elements.append("input[type=" + attrs["type"].lower() + "]")

    def handle_endtag(self, tag):
        if tag == "a" and self.current_link is not None:
            self.links.append({"url": self.current_link["url"], "text": "".join(self.current_link["text"]).strip()})
            self.current_link = None

    def handle_data(self, data):
        self.text.append(data)
        if self.current_link is not None:
            self.current_link["text"].append(data)


def domain_of(value):
    match = re.search(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", value or "", re.I)
    return match.group(1).rstrip(".").lower() if match else ""


def extension_of(filename):
    filename = (filename or "").lower().rstrip(".")
    return "." + filename.rsplit(".", 1)[-1] if "." in filename else ""


def unique(values):
    return list(dict.fromkeys(v for v in values if v))


def analyze(raw_email):
    message = Parser(policy=policy.default).parsestr(raw_email)
    findings, score = [], 0

    def flag(title, text, points=0, severity=""):
        nonlocal score
        score += points
        findings.append({"title": title, "text": text, "severity": severity})

    def header(name):
        return str(message.get(name, "")).strip()

    from_domain = domain_of(header("From"))
    reply_domain = domain_of(header("Reply-To"))
    return_domain = domain_of(header("Return-Path"))
    headers = {
        "From": header("From"), "To": header("To"), "CC": header("Cc"),
        "Reply-To": header("Reply-To"), "Return-Path": header("Return-Path"),
        "Subject": header("Subject"), "Date": header("Date"),
        "Message-ID": header("Message-ID"),
    }
    raw_header_names = ("From", "To", "Cc", "Reply-To", "Return-Path", "Subject", "Date",
                        "Message-ID", "Received", "Authentication-Results", "Received-SPF",
                        "DKIM-Signature", "ARC-Authentication-Results", "ARC-Seal")
    raw_headers = "\n".join(f"{name}: {value}" for name in raw_header_names
                            for value in message.get_all(name, []) if value)
    presence_names = ("From", "To", "Cc", "Reply-To", "Return-Path", "Subject", "Date",
                      "Message-ID", "Received", "Authentication-Results", "Received-SPF",
                      "DKIM-Signature", "ARC-Authentication-Results", "ARC-Seal")
    raw_header_presence = {name: bool(message.get_all(name, [])) for name in presence_names}

    # These values are parsed from supplied headers; they are not independently verified.
    auth_results = " ".join(str(v) for v in message.get_all("Authentication-Results", []))
    received_spf = " ".join(str(v) for v in message.get_all("Received-SPF", []))
    authentication = []
    for name in ("SPF", "DKIM", "DMARC", "ARC"):
        if name == "ARC":
            found = re.search(r"\barc(?:-authentication-results)?\s*=\s*(pass|fail|none|temperror|permerror)\b", auth_results, re.I)
            if not found:
                arc_text = " ".join(str(v) for v in message.get_all("ARC-Authentication-Results", []))
                found = re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*(pass|fail)\b", arc_text, re.I)
                status = "present; inspect chain" if message.get_all("ARC-Authentication-Results", []) else "not reported"
            else:
                status = found.group(1).lower()
        else:
            found = re.search(rf"\b{name.lower()}\s*=\s*(pass|fail|softfail|none|neutral|temperror|permerror|bestguesspass)\b", auth_results, re.I)
            if name == "SPF" and not found:
                found = re.search(r"^\s*(pass|fail|softfail|none|neutral|temperror|permerror)\b", received_spf, re.I)
            status = found.group(1).lower() if found else "not reported"
        authentication.append({"name": name, "status": status})
        if status in ("fail", "softfail", "permerror"):
            points = 4 if name == "DMARC" else 2
            flag(name + " reported failure", f"The supplied headers report {name} {status}. This is a reported result, not independent verification.", points, "high" if name == "DMARC" else "")
        elif status in ("none", "neutral", "temperror"):
            flag(name + " not confirmed", f"The available headers report {name} {status}; this does not establish that the message is malicious.", 1)
    if not message.get("Authentication-Results"):
        flag("Authentication results missing", "No Authentication-Results header was included; SPF, DKIM, and DMARC cannot be confirmed from this message.", 0)

    if not from_domain:
        flag("Sender address unclear", "The From header is missing or does not contain a recognizable email address.", 1)
    if reply_domain and from_domain and reply_domain != from_domain:
        flag("Reply-To domain differs", f"Reply-To uses {reply_domain}, which differs from the From domain {from_domain}.", 2)
    if return_domain and from_domain and return_domain != from_domain:
        flag("Return-Path domain differs", f"Return-Path uses {return_domain}, which differs from From domain {from_domain}; this can be legitimate but deserves review.", 1)

    body_text, body_html, links, attachments = "", "", [], []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        content_type = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            ext = extension_of(filename)
            mime = content_type.lower()
            mime_ext_mismatch = (
                (ext in {".exe", ".dll", ".scr", ".msi"} and mime not in {"application/octet-stream", "application/x-msdownload", "application/vnd.microsoft.portable-executable"}) or
                (ext in {".pdf"} and mime not in {"application/pdf", "application/octet-stream"}) or
                (ext in {".docx", ".xlsx", ".pptx"} and "openxmlformats" not in mime and mime != "application/octet-stream")
            )
            item = {
                "filename": filename or "[unnamed attachment]",
                "content_type": content_type,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "risky": ext in RISKY_EXTENSIONS,
                "extension_mismatch": bool(mime_ext_mismatch),
            }
            attachments.append(item)
            if item["risky"]:
                flag("Potentially risky attachment", f"Attachment {item['filename']} has a file extension often abused in phishing or malware delivery.", 3, "high")
            if item["extension_mismatch"]:
                flag("Attachment type mismatch", f"Attachment {item['filename']} has a file extension that may not match its declared MIME type; inspect safely.", 2, "high")
            continue
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
            if isinstance(content, bytes):
                content = content.decode("utf-8", "replace")
        except (LookupError, UnicodeError, ValueError):
            continue
        if content_type == "text/html":
            body_html += ("\n" if body_html else "") + content
            parser = MessageText()
            parser.feed(content)
            body_text += " " + " ".join(parser.text)
            links.extend(parser.links)
            if parser.hidden_elements:
                flag("Hidden HTML elements", "HTML includes hidden elements or password/email input fields; review the source to determine whether they are deceptive.", 1)
            if parser.forms:
                flag("HTML form present", "The HTML body contains a form. Email forms can be suspicious, especially if they request credentials.", 2, "high")
            if parser.script_tags:
                flag("Script tag in HTML", "The HTML body contains script tags. Many mail clients block scripts, but the source should still be reviewed.", 1)
        else:
            body_text += " " + content
            links.extend({"url": m, "text": ""} for m in re.findall(r"https?://[^\s<>\"']+", content, re.I))

    # Collect visible plain-text URLs as well as HTML anchor targets, then normalize/deduplicate.
    normalized_links, suspicious_hosts, misleading_links = [], set(), set()
    for link in links:
        url = (link.get("url") or "").strip().strip(".,);]}")
        if not url:
            continue
        parsed = urlsplit(url if "://" in url else "https://" + url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            continue
        reason = []
        if parsed.scheme.lower() == "http":
            reason.append("unencrypted HTTP")
        if host in URL_SHORTENERS:
            reason.append("URL shortener")
        if host.startswith("xn--") or any(label.startswith("xn--") for label in host.split(".")):
            reason.append("punycode/internationalized domain")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            reason.append("IP address used as host")
        if "@" in parsed.netloc:
            reason.append("userinfo in URL")
        visible = (link.get("text") or "").strip()
        visible_match = re.search(r"(?:(?:https?://)?(?:www\.)?)([A-Z0-9.-]+\.[A-Z]{2,})", visible, re.I)
        if visible_match:
            visible_host = visible_match.group(1).lower().removeprefix("www.")
            if visible_host != host and not host.endswith("." + visible_host):
                misleading_links.add(visible_host + " → " + host)
                reason.append("visible text differs from destination")
        if reason:
            suspicious_hosts.add(host)
        normalized_links.append({"url": url, "host": host, "text": visible, "reason": ", ".join(reason) if reason else "No simple URL pattern flagged"})
    # Deduplicate identical URLs without losing order.
    seen = set()
    normalized_links = [x for x in normalized_links if not (x["url"] in seen or seen.add(x["url"]))]
    if suspicious_hosts:
        flag("Suspicious URL patterns", "Review these URL hosts/patterns: " + ", ".join(sorted(suspicious_hosts)) + ".", 2)
    if misleading_links:
        flag("Misleading link text", "Displayed address differs from destination: " + ", ".join(sorted(misleading_links)) + ".", 3, "high")

    pressure = re.search(r"\b(verify your password|confirm your password|wire transfer|gift card|account will be (?:closed|suspended)|urgent action required|send your password|reset your password immediately|payment overdue|unusual sign-in)\b", body_text, re.I)
    if pressure:
        flag("Possible social-engineering language", "The body contains urgency, credential, payment, or account-pressure language commonly seen in phishing.", 1)

    received = [str(v) for v in message.get_all("Received", [])]
    if received:
        ips = unique(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ".join(received)))
        if ips:
            # These are extracted IP strings; no geolocation or reputation claims are made.
            pass

    iocs = {
        "Domains": unique([x["host"] for x in normalized_links] + [from_domain, reply_domain, return_domain]),
        "IPv4 addresses": unique(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ".join(received) + " " + " ".join(x["url"] for x in normalized_links))),
        "Email addresses": unique(re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", raw_email, re.I)),
        "Attachment SHA-256": unique([x["sha256"] for x in attachments]),
    }
    if score >= 4:
        verdict, level = "High risk", "high"
    elif score >= 2:
        verdict, level = "Review carefully", "review"
    else:
        verdict, level = "No obvious red flags", "clear"
    return {
        "verdict": verdict, "level": level, "score": score,
        "summary": f"From: {from_domain or 'not identified'} · {len(normalized_links)} URL(s) · {len(attachments)} attachment(s) · {len(findings)} finding(s).",
        "headers": headers, "raw_headers": raw_headers, "raw_header_presence": raw_header_presence,
        "authentication": authentication, "findings": findings,
        "links": normalized_links, "attachments": attachments,
        "iocs": iocs,
        "body": {"text": re.sub(r"[ \t]+", " ", body_text).strip(), "html": body_html},
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        content = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        if self.path == "/virustotal":
            self.handle_virustotal()
            return
        if self.path.startswith("/threatintel/"):
            service = self.path.rsplit("/", 1)[-1]
            self.handle_threatintel(service)
            return
        if self.path != "/analyze":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                self.send_json({"error": "Empty request."}, 400)
                return
            if length > MAX_MESSAGE_LENGTH:
                self.send_json({"error": "Email is larger than the 1 MB limit."}, 413)
                return
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                self.send_json({"error": "Request must be a JSON object."}, 400)
                return
            raw_email = payload.get("email", "")
            if not isinstance(raw_email, str) or not raw_email.strip():
                self.send_json({"error": "Paste an email message before analyzing."}, 400)
                return
            if len(raw_email.encode("utf-8")) > MAX_MESSAGE_LENGTH:
                self.send_json({"error": "Email is larger than the 1 MB limit."}, 413)
                return
            self.send_json(analyze(raw_email))
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "The request could not be read as valid JSON."}, 400)
        except Exception:
            self.send_json({"error": "Analysis failed. Check that the input is a valid raw email."}, 400)

    def handle_virustotal(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 200_000:
                self.send_json({"error": "Invalid request size."}, 400)
                return
            payload = json.loads(self.rfile.read(length))
            api_key = payload.get("api_key", "")
            if not isinstance(api_key, str) or not api_key.strip() or len(api_key) > 500:
                self.send_json({"error": "Enter a valid VirusTotal API key."}, 400)
                return
            links = payload.get("links", [])
            hashes = payload.get("hashes", [])
            if not isinstance(links, list) or not isinstance(hashes, list):
                self.send_json({"error": "Invalid indicators."}, 400)
                return
            # Avoid exhausting the VirusTotal Public API quota; query up to 4 unique indicators.
            indicators = []
            for value in hashes:
                if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
                    indicators.append(("file hash", value.lower(), "files/" + value.lower(), "https://www.virustotal.com/gui/file/" + value.lower()))
            for value in links:
                if isinstance(value, str) and value.startswith(("http://", "https://")):
                    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
                    indicators.append(("URL", value, "urls/" + encoded, "https://www.virustotal.com/gui/url/" + encoded))
            unique_indicators = []
            seen = set()
            for item in indicators:
                if (item[0], item[1]) not in seen:
                    seen.add((item[0], item[1]))
                    unique_indicators.append(item)
            if not unique_indicators:
                self.send_json({"results": [], "note": "No valid attachment SHA-256 hashes or HTTP(S) URLs were found."})
                return
            results = []
            for kind, indicator, endpoint, report_url in unique_indicators[:4]:
                req = Request("https://www.virustotal.com/api/v3/" + endpoint,
                              headers={"x-apikey": api_key.strip(), "accept": "application/json", "User-Agent": "MailCheck-local/1.0"})
                try:
                    with urlopen(req, timeout=12) as response:
                        report = json.loads(response.read().decode("utf-8"))
                    attrs = report.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = int(stats.get("malicious", 0) or 0)
                    suspicious = int(stats.get("suspicious", 0) or 0)
                    harmless = int(stats.get("harmless", 0) or 0)
                    undetected = int(stats.get("undetected", 0) or 0)
                    status = "Malicious" if malicious else ("Suspicious" if suspicious else ("No detections" if stats else "Report found"))
                    results.append({"kind": kind, "indicator": indicator, "status": status,
                                    "malicious": malicious, "suspicious": suspicious,
                                    "harmless": harmless, "undetected": undetected,
                                    "detections": malicious + suspicious, "url": report_url})
                except HTTPError as exc:
                    if exc.code == 404:
                        msg = "No existing report found. This tool does not submit new scans."
                    elif exc.code == 401:
                        self.send_json({"error": "VirusTotal rejected the API key (401 Unauthorized)."}, 401)
                        return
                    elif exc.code == 403:
                        self.send_json({"error": "VirusTotal denied this request (403). Check API permissions and plan limits."}, 403)
                        return
                    elif exc.code == 429:
                        self.send_json({"error": "VirusTotal rate limit reached (429). Wait before trying again; the Public API is limited to 4 requests per minute."}, 429)
                        return
                    else:
                        msg = "VirusTotal returned HTTP " + str(exc.code) + "."
                    results.append({"kind": kind, "indicator": indicator, "status": "Unavailable", "message": msg, "url": report_url})
                except (URLError, TimeoutError, json.JSONDecodeError, ValueError):
                    results.append({"kind": kind, "indicator": indicator, "status": "Unavailable", "message": "Network error or unexpected VirusTotal response.", "url": report_url})
            self.send_json({"results": results, "note": "Checked up to 4 indicators using existing VirusTotal reports. No files, email body, or new scans were uploaded."})
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Could not parse VirusTotal request."}, 400)
        except Exception:
            self.send_json({"error": "VirusTotal lookup failed."}, 500)

    def read_api_payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 200_000:
            raise ValueError("Invalid request size.")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("Request must be a JSON object.")
        return payload

    @staticmethod
    def api_json(url, headers=None, data=None, timeout=12):
        body = None
        req_headers = {"User-Agent": "MailCheck-local/1.1", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        if data is not None:
            body = urlencode(data).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = Request(url, data=body, headers=req_headers)
        with urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    def handle_threatintel(self, service):
        allowed = {"abuseipdb", "urlhaus", "phishtank", "otx"}
        if service not in allowed:
            self.send_json({"error": "Unknown threat-intelligence service."}, 404)
            return
        try:
            payload = self.read_api_payload()
            api_key = payload.get("api_key", "")
            if not isinstance(api_key, str) or len(api_key) > 500:
                self.send_json({"error": "Invalid API key value."}, 400)
                return
            results = []
            if service == "abuseipdb":
                if not api_key.strip():
                    self.send_json({"error": "Enter an AbuseIPDB API key."}, 400); return
                ips = self.clean_indicators(payload.get("ips", []), r"(?:\d{1,3}\.){3}\d{1,3}", 5)
                for ip in ips:
                    try:
                        data = self.api_json("https://api.abuseipdb.com/api/v2/check?" + urlencode({"ipAddress": ip, "maxAgeInDays": "90"}),
                                             {"Key": api_key.strip(), "Accept": "application/json"})
                        d = data.get("data", {})
                        score = int(d.get("abuseConfidenceScore", 0) or 0)
                        status = "Abusive / high risk" if score >= 50 else ("Reported / review" if score > 0 else "No abuse confidence")
                        results.append({"kind":"IPv4", "indicator":ip, "status":status,
                                        "summary":f"Abuse confidence: {score}% · Reports: {d.get('totalReports', 0)} · ISP: {d.get('isp', 'unknown')} · Country: {d.get('countryCode', 'unknown')}",
                                        "url":"https://www.abuseipdb.com/check/" + ip})
                    except Exception as exc: results.append(self.lookup_error("IPv4", ip, exc))
                note = "Checked up to 5 IP addresses. Abuse confidence is a signal, not proof of malicious activity."
            elif service == "urlhaus":
                links = self.clean_indicators(payload.get("links", []), r"https?://\S+", 5)
                for link in links:
                    try:
                        headers = {"Auth-Key": api_key.strip()} if api_key.strip() else {}
                        data = self.api_json("https://urlhaus-api.abuse.ch/v1/url/", headers, {"url": link})
                        if data.get("query_status") == "ok":
                            info = data.get("url", {}) if isinstance(data.get("url"), dict) else data
                            threat = info.get("threat", "malware")
                            results.append({"kind":"URL", "indicator":link, "status":"Listed — malware URL",
                                            "summary":f"Threat: {threat} · URL status: {info.get('url_status', 'unknown')} · Host: {info.get('host', 'unknown')}",
                                            "url":info.get("urlhaus_reference") or "https://urlhaus.abuse.ch/browse/"})
                        elif data.get("query_status") in ("no_results", "invalid_url"):
                            results.append({"kind":"URL", "indicator":link, "status":"Not found in URLhaus", "summary":"No matching URLhaus record was returned."})
                        else:
                            results.append({"kind":"URL", "indicator":link, "status":"Unavailable", "message":"URLhaus response: " + str(data.get("query_status", "unexpected response"))})
                    except HTTPError as exc:
                        msg = "URLhaus rejected the request (HTTP " + str(exc.code) + "). Check whether an Auth-Key is required and valid."
                        results.append({"kind":"URL", "indicator":link, "status":"Unavailable", "message":msg})
                    except Exception as exc: results.append(self.lookup_error("URL", link, exc))
                note = "Checked up to 5 URLs against URLhaus. A missing match does not prove a URL is safe."
            elif service == "phishtank":
                links = self.clean_indicators(payload.get("links", []), r"https?://\S+", 5)
                for link in links:
                    try:
                        form = {"url": link, "format": "json"}
                        if api_key.strip(): form["app_key"] = api_key.strip()
                        data = self.api_json("https://checkurl.phishtank.com/checkurl/", {"User-Agent": "phishtank/mailcheck"}, form)
                        item = data.get("results", {}) if isinstance(data.get("results"), dict) else {}
                        if item.get("in_database") and item.get("valid"):
                            status = "Confirmed phishing listing"
                        elif item.get("in_database"):
                            status = "Listed — validity not confirmed"
                        else:
                            status = "Not listed in PhishTank"
                        results.append({"kind":"URL", "indicator":link, "status":status,
                                        "summary":f"In database: {item.get('in_database', False)} · Valid: {item.get('valid', False)} · Verified: {item.get('verified', False)}",
                                        "url":item.get("phish_detail_page")})
                    except Exception as exc: results.append(self.lookup_error("URL", link, exc))
                note = "Checked up to 5 URLs against PhishTank. Not listed does not mean safe. API key is optional where supported."
            else:  # AlienVault OTX
                if not api_key.strip():
                    self.send_json({"error": "Enter an AlienVault OTX API key."}, 400); return
                ips = self.clean_indicators(payload.get("ips", []), r"(?:\d{1,3}\.){3}\d{1,3}", 3)
                domains = self.clean_indicators(payload.get("domains", []), r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 3)
                hashes = self.clean_indicators(payload.get("hashes", []), r"[a-fA-F0-9]{64}", 3)
                indicators = [("IPv4", "IPv4", x) for x in ips] + [("domain", "domain", x) for x in domains] + [("file hash", "file", x.lower()) for x in hashes]
                for kind, path_kind, value in indicators[:8]:
                    try:
                        url = "https://otx.alienvault.com/api/v1/indicators/" + path_kind + "/" + value + "/general"
                        data = self.api_json(url, {"X-OTX-API-KEY": api_key.strip()})
                        pulse_count = int(data.get("pulse_info", {}).get("count", 0) or 0)
                        status = "Threat pulses found" if pulse_count else "No threat pulses found"
                        results.append({"kind":kind, "indicator":value, "status":status,
                                        "summary":f"Pulse count: {pulse_count} · Reputation: {data.get('reputation', 'not provided')}",
                                        "url":"https://otx.alienvault.com/indicator/" + path_kind + "/" + value})
                    except Exception as exc: results.append(self.lookup_error(kind, value, exc))
                note = "Checked up to 8 IP/domain/hash indicators against OTX. Pulse absence is not proof of safety."
            self.send_json({"results": results, "note": note})
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Could not parse threat-intelligence request."}, 400)
        except Exception:
            self.send_json({"error": "Threat-intelligence lookup failed."}, 500)

    @staticmethod
    def clean_indicators(values, pattern, limit):
        if not isinstance(values, list): return []
        out = []
        for value in values:
            if isinstance(value, str):
                value = value.strip()
                if value and re.fullmatch(pattern, value, re.I) and value not in out:
                    out.append(value)
            if len(out) >= limit: break
        return out

    @staticmethod
    def lookup_error(kind, indicator, exc):
        if isinstance(exc, HTTPError):
            message = "Provider returned HTTP " + str(exc.code) + ". Check API key, permissions and rate limits."
        elif isinstance(exc, URLError) or isinstance(exc, TimeoutError):
            message = "Network error or provider timeout."
        else:
            message = "Provider returned an unexpected response."
        return {"kind": kind, "indicator": indicator, "status": "Unavailable", "message": message}

    def send_json(self, payload, status=200):
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Mail Check is running at http://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    print("Optional threat-intelligence providers: VirusTotal, AbuseIPDB, URLhaus, PhishTank, AlienVault OTX.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMail Check stopped.")
        server.server_close()
