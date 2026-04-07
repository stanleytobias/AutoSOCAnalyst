"""
Level 1 SOC Analyst Agent — Azure Function (Claude Sonnet via Azure AI Foundry)
POST /api/triage  →  Body: {"incident_number": 57728}

Required roles on the Function's Managed Identity:
  - Microsoft Sentinel Responder      (post comments, read incidents)
  - Log Analytics Reader              (run KQL queries)
  - Cognitive Services OpenAI User    (call Claude via Azure AI Foundry)

Env vars:
  FOUNDRY_ENDPOINT   — e.g. https://<your-resource>.services.ai.azure.com/anthropic/v1
  SUBSCRIPTION_ID / RESOURCE_GROUP / WORKSPACE_NAME / WORKSPACE_ID
"""

import json
import logging
import os
import uuid

import anthropic
import azure.functions as func
import requests
from azure.identity import DefaultAzureCredential

app    = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
SUBSCRIPTION_ID  = os.environ["SUBSCRIPTION_ID"]   # Azure Subscription ID (GUID)
RESOURCE_GROUP   = os.environ["RESOURCE_GROUP"]    # e.g. "my-security-rg"
WORKSPACE_NAME   = os.environ["WORKSPACE_NAME"]    # Log Analytics workspace name
WORKSPACE_ID     = os.environ["WORKSPACE_ID"]      # Log Analytics workspace ID (GUID)
FOUNDRY_ENDPOINT = os.environ["FOUNDRY_ENDPOINT"]  # e.g. "https://<resource>.services.ai.azure.com/anthropic"
MODEL           = "SOC-Automation-claude-sonnet-4-6"
MAX_TOKENS      = 8000
MAX_TOOL_ROUNDS = 20

SENTINEL_BASE = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
    f"/providers/Microsoft.SecurityInsights"
)

_credential = DefaultAzureCredential()


def _anthropic_client():
    """Build an Anthropic client using API key auth to Azure AI Foundry."""
    api_key = os.environ.get("FOUNDRY_API_KEY")
    return anthropic.Anthropic(
        api_key=api_key,
        base_url=FOUNDRY_ENDPOINT,
        default_headers={"api-key": api_key},   # Foundry uses api-key, not x-api-key
    )


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _mgmt_headers():
    token = _credential.get_token("https://management.azure.com/.default").token
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def _logs_headers():
    token = _credential.get_token("https://api.loganalytics.io/.default").token
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ── REST helpers ───────────────────────────────────────────────────────────────

def _rest_get(url):
    r = requests.get(url, headers=_mgmt_headers(), timeout=30)
    r.raise_for_status()
    return r.json()

def _rest_post(url, body=None):
    r = requests.post(url, headers=_mgmt_headers(), json=body or {}, timeout=30)
    r.raise_for_status()
    return r.json()

def _rest_put(url, body):
    r = requests.put(url, headers=_mgmt_headers(), json=body, timeout=30)
    r.raise_for_status()
    return r.json()

def _kql(query, timespan="P7D"):
    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    r   = requests.post(url, headers=_logs_headers(),
                        json={"query": query, "timespan": timespan}, timeout=60)
    r.raise_for_status()
    tables = r.json().get("tables", [])
    if not tables:
        return []
    cols = [c["name"] for c in tables[0]["columns"]]
    return [dict(zip(cols, row)) for row in tables[0]["rows"]]


# ── Tool implementations ───────────────────────────────────────────────────────

def get_incident(incident_number):
    url   = (f"{SENTINEL_BASE}/incidents?api-version=2023-11-01"
             f"&$filter=properties/incidentNumber eq {incident_number}")
    items = _rest_get(url).get("value", [])
    if not items:
        return {"error": f"Incident {incident_number} not found"}
    inc, props = items[0], items[0].get("properties", {})
    return {
        "incident_id":    inc.get("name"),
        "title":          props.get("title"),
        "description":    props.get("description"),
        "severity":       props.get("severity"),
        "status":         props.get("status"),
        "classification": props.get("classification"),
        "owner":          props.get("owner", {}).get("userPrincipalName"),
        "created_time":   props.get("createdTimeUtc"),
        "last_modified":  props.get("lastModifiedTimeUtc"),
        "labels":         [l.get("labelName") for l in props.get("labels", [])],
    }

def get_incident_alerts(incident_id):
    url  = f"{SENTINEL_BASE}/incidents/{incident_id}/alerts?api-version=2023-11-01"
    data = _rest_post(url)
    return [{
        "alert_name":          p.get("alertDisplayName"),
        "alert_type":          p.get("alertType"),
        "severity":            p.get("severity"),
        "description":         p.get("description"),
        "system_alert_id":     p.get("systemAlertId"),
        "product_name":        p.get("productName"),
        "start_time":          p.get("startTimeUtc"),
        "end_time":            p.get("endTimeUtc"),
        "extended_properties": p.get("extendedProperties", {}),
    } for a in data.get("value", []) for p in [a.get("properties", {})]]

def get_incident_entities(incident_id):
    url      = f"{SENTINEL_BASE}/incidents/{incident_id}/entities?api-version=2023-11-01"
    entities = []
    for e in _rest_post(url).get("entities", []):
        kind, p = e.get("kind"), e.get("properties", {})
        entry   = {"kind": kind}
        if kind == "Account":
            entry.update({"upn": p.get("userPrincipalName") or p.get("accountName"),
                          "aad_user_id": p.get("aadUserId"), "display_name": p.get("displayName")})
        elif kind == "Host":
            entry.update({"hostname": p.get("hostName"), "fqdn": p.get("dnsDomain"),
                          "azure_id": p.get("azureID"), "os": p.get("osFamily")})
        elif kind == "Ip":
            entry.update({"ip": p.get("address"), "location": p.get("location", {})})
        elif kind == "Url":
            entry.update({"url": p.get("url")})
        elif kind in ("File", "FileHash"):
            entry.update({"filename": p.get("fileName"), "hash": p.get("hashValue"),
                          "algorithm": p.get("algorithm")})
        elif kind == "Process":
            entry.update({"command": p.get("commandLine"), "process_id": p.get("processId")})
        else:
            entry.update({"raw_properties": p})
        entities.append(entry)
    return entities

def get_alert_raw_query(system_alert_id):
    rows = _kql(f"SecurityAlert | where SystemAlertId == '{system_alert_id}' "
                f"| project AlertName, Description, AlertLink, ExtendedProperties | limit 1")
    if not rows:
        return "No alert found"
    row = rows[0]
    ext = row.get("ExtendedProperties", "{}")
    if isinstance(ext, str):
        try: ext = json.loads(ext)
        except Exception: pass
    return {
        "alert_name":          row.get("AlertName"),
        "description":         row.get("Description"),
        "alert_link":          row.get("AlertLink"),
        "detection_query":     ext.get("Query") if isinstance(ext, dict) else None,
        "extended_properties": ext,
    }

def run_kql_query(query, timespan="P7D"):
    if "| limit" not in query.lower() and "| take" not in query.lower():
        query = query.rstrip() + "\n| limit 50"
    return _kql(query, timespan)

def get_ueba_insights(user_upn=None, account_name=None):
    if not user_upn and not account_name:
        return {"error": "Provide user_upn or account_name"}
    f   = f"| where UserPrincipalName =~ '{user_upn}'" if user_upn else f"| where UserName =~ '{account_name}'"
    kql = (f"BehaviorAnalytics {f} | summarize arg_max(TimeGenerated,*), "
           f"TotalActivities=count(), AnomalousActivities=countif(ActivityInsights!='{{}}') "
           f"by UserPrincipalName,UserName | project UserPrincipalName,UserName,"
           f"TotalActivities,AnomalousActivities,InvestigationPriority,ActivityInsights,"
           f"DevicesInsights,UsersInsights,TimeGenerated | limit 5")
    rows = _kql(kql)
    return {"rows": rows} if rows else {"rows": [], "note": "No UEBA data found"}

def get_signin_logs(user_upn=None, ip_address=None, days=7):
    filters = []
    if user_upn:   filters.append(f"UserPrincipalName =~ '{user_upn}'")
    if ip_address: filters.append(f"IPAddress == '{ip_address}'")
    fc  = " and ".join(filters) if filters else "true"
    kql = (f"SigninLogs | where {fc} | summarize SigninCount=count(),"
           f"FailureCount=countif(ResultType!='0'),SuccessCount=countif(ResultType=='0'),"
           f"Countries=make_set(Location,10),AppNames=make_set(AppDisplayName,10),"
           f"LastSeen=max(TimeGenerated),FirstSeen=min(TimeGenerated),"
           f"RiskLevels=make_set(RiskLevelDuringSignIn,5) by UserPrincipalName,IPAddress,UserAgent"
           f" | top 20 by SigninCount desc")
    return _kql(kql, f"P{days}D")

def get_audit_logs(user_upn=None, ip_address=None, days=7):
    filters = []
    if user_upn:   filters.append(f"InitiatedBy.user.userPrincipalName =~ '{user_upn}'")
    if ip_address: filters.append(f"InitiatedBy.user.ipAddress == '{ip_address}'")
    fc  = " and ".join(filters) if filters else "true"
    kql = (f"AuditLogs | where {fc} | project TimeGenerated,OperationName,Result,"
           f"TargetResources,InitiatedBy,LoggedByService | top 30 by TimeGenerated desc")
    return _kql(kql, f"P{days}D")

def get_device_timeline(hostname, days=3):
    kql = (f"DeviceProcessEvents | where DeviceName startswith '{hostname}' "
           f"| project TimeGenerated,DeviceName,InitiatingProcessFileName,"
           f"FileName,ProcessCommandLine,AccountName,FolderPath | top 50 by TimeGenerated desc")
    return _kql(kql, f"P{days}D")

def post_sentinel_comment(incident_id, comment):
    cid  = str(uuid.uuid4())
    url  = f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{cid}?api-version=2023-11-01"
    _rest_put(url, {"properties": {"message": comment}})
    return {"status": "comment_posted", "comment_id": cid}


# ── Tool schema (Anthropic format) ────────────────────────────────────────────

TOOLS = [
    {
        "name": "get_incident",
        "description": "Fetch Sentinel incident details by incident number.",
        "input_schema": {"type": "object",
            "properties": {"incident_number": {"type": "integer", "description": "e.g. 57728"}},
            "required": ["incident_number"]}
    },
    {
        "name": "get_incident_alerts",
        "description": "Get all alerts for a Sentinel incident. Returns systemAlertIds and extendedProperties.",
        "input_schema": {"type": "object",
            "properties": {"incident_id": {"type": "string", "description": "ARM name from get_incident"}},
            "required": ["incident_id"]}
    },
    {
        "name": "get_incident_entities",
        "description": "Get entities (Accounts, Hosts, IPs, URLs, Hashes) from the incident.",
        "input_schema": {"type": "object",
            "properties": {"incident_id": {"type": "string"}},
            "required": ["incident_id"]}
    },
    {
        "name": "get_alert_raw_query",
        "description": "Get the original frozen KQL detection query from an alert's ExtendedProperties.",
        "input_schema": {"type": "object",
            "properties": {"system_alert_id": {"type": "string", "description": "from get_incident_alerts"}},
            "required": ["system_alert_id"]}
    },
    {
        "name": "run_kql_query",
        "description": "Run arbitrary KQL against Log Analytics. timespan: ISO 8601 (P7D, P1D, PT1H).",
        "input_schema": {"type": "object",
            "properties": {
                "query":    {"type": "string"},
                "timespan": {"type": "string", "description": "default P7D"}
            },
            "required": ["query"]}
    },
    {
        "name": "get_ueba_insights",
        "description": "UEBA BehaviorAnalytics for a user — priority, anomalies, location fluctuations.",
        "input_schema": {"type": "object",
            "properties": {
                "user_upn":     {"type": "string"},
                "account_name": {"type": "string"}
            }}
    },
    {
        "name": "get_signin_logs",
        "description": "Azure AD sign-in logs for a user or IP. Failures, countries, apps, risk levels.",
        "input_schema": {"type": "object",
            "properties": {
                "user_upn":   {"type": "string"},
                "ip_address": {"type": "string"},
                "days":       {"type": "integer", "description": "default 7"}
            }}
    },
    {
        "name": "get_audit_logs",
        "description": "Azure AD Audit Logs — admin ops, permission changes, MFA modifications.",
        "input_schema": {"type": "object",
            "properties": {
                "user_upn":   {"type": "string"},
                "ip_address": {"type": "string"},
                "days":       {"type": "integer", "description": "default 7"}
            }}
    },
    {
        "name": "get_device_timeline",
        "description": "MDE DeviceProcessEvents for a host.",
        "input_schema": {"type": "object",
            "properties": {
                "hostname": {"type": "string"},
                "days":     {"type": "integer", "description": "default 3"}
            },
            "required": ["hostname"]}
    },
    {
        "name": "post_sentinel_comment",
        "description": "Post completed triage report to the incident. Call ONCE when all investigation is done.",
        "input_schema": {"type": "object",
            "properties": {
                "incident_id": {"type": "string"},
                "comment":     {"type": "string"}
            },
            "required": ["incident_id", "comment"]}
    },
]

SYSTEM_PROMPT = """You are a Level 1 SOC Analyst at {os.environ.get("ORGANIZATION_NAME", "[Your Organization]")}. Investigate Microsoft Sentinel incidents methodically.

## Step 1 — Classify the alert type before running any queries
Read the incident title and alert descriptions, then classify:
- **Endpoint** — mentions a host, process, file, registry, or RMM tool
- **Identity/App** — mentions a user, sign-in, Azure AD, OAuth, URL added to app, MFA, audit event
- **Email/Phishing** — mentions a phishing email, URL click, attachment, mail delivery
- **Network/IP** — mentions an external IP, DNS, firewall, C2
- **Azure Resource** — mentions an Azure service, Cognitive Services, storage account, subscription
- **Credential Abuse** — mentions failed logins, password spray, brute force

Run ONLY the queries relevant to the alert type. Do not run DeviceProcessEvents for identity or email alerts.

## Step 2 — Gather context
1. get_incident
2. get_incident_alerts — note the exact alert title, any entity names, and the detection score/confidence if present
3. get_incident_entities
4. get_alert_raw_query — read the `description` field carefully. It tells you what the rule is designed to detect (e.g. "detects presence of RMM tools" vs "detects execution of QuickAssist.exe"). Use this to infer detection intent before running queries:
   - "presence" / "installed" / "detected on device" → check DeviceFileEvents, DeviceRegistryEvents, SoftwareInventory
   - "execution" / "ran" / "launched" → check DeviceProcessEvents
   - "sign-in" / "authentication" / "login" → check SigninLogs
   - "added" / "modified" / "configuration change" → check AuditLogs, AzureActivity
   If description is empty, fall back to inferring from the alert title and alert type.

## Step 3 — Investigate by alert type

### Endpoint alerts
a. get_device_timeline on the host
b. Check whether the alert is about **execution** or **presence/installation**:
   - Execution → search DeviceProcessEvents:
     `DeviceProcessEvents | where DeviceName has "<host>" and (FileName has "<process>" or ProcessCommandLine has "<process>") | project Timestamp, FileName, FolderPath, ProcessCommandLine, AccountName | take 20`
   - Presence/installation → search DeviceFileEvents and DeviceRegistryEvents:
     `DeviceFileEvents | where DeviceName has "<host>" and FileName has "<process>" | project Timestamp, FileName, FolderPath, ActionType | take 20`
c. If the named process is NOT found, run a time-windowed query to see what WAS present:
   `DeviceProcessEvents | where DeviceName has "<host>" | where Timestamp between(datetime(<alert_time> - 5m) .. datetime(<alert_time> + 5m)) | project Timestamp, FileName, FolderPath, ProcessCommandLine | take 30`
d. Compare actual process/path vs alert title. If they differ → likely False Positive, state the actual process and path found.

### Identity/App alerts
a. get_signin_logs — if empty at 7 days, retry at 30 days: add `days=30`
b. get_audit_logs
c. get_ueba_insights
d. For "URL added to app" alerts: check if the domain is Azure-owned (*.azurewebsites.net, *.azure.com, *.microsoft.com) — these are not unknown external domains
e. Check for other users affected by the same activity if relevant

### Email/Phishing alerts
a. A detection score of 100.0 means the email system has confirmed this IS a phishing email — the alert is a True Positive
b. Check whether the user clicked any links:
   `EmailUrlInfo | where RecipientEmailAddress has "<user>" | project Timestamp, Url, NetworkMessageId | order by Timestamp desc | take 20`
   or: `UrlClickEvents | where AccountUpn has "<user>" | project Timestamp, Url, ActionType | order by Timestamp desc | take 20`
c. Check sign-in logs immediately after the email open time for logins from new IPs/locations
d. Check if other users received the same email:
   `EmailEvents | where Subject has "<subject>" | project Timestamp, RecipientEmailAddress, DeliveryAction | take 20`
e. Note the email subject for social engineering context (e.g. "FCO" = advance-fee fraud, "Invoice" = BEC)

### Network/IP alerts
a. run_kql_query on ThreatIntelligenceIndicator for the IP:
   `ThreatIntelligenceIndicator | where NetworkIP has "<ip>" or NetworkDestinationIP has "<ip>" | project TimeGenerated, ThreatType, Description, ConfidenceScore | take 10`
b. Check for other users/hosts connecting to the same IP (spray or C2 pattern)
c. get_signin_logs by IP address

### Credential abuse / failed auth alerts
a. get_signin_logs — start with 7 days; if empty, widen to 30 days
b. Check for multiple accounts targeted from the same IP (password spray):
   `SigninLogs | where IPAddress == "<ip>" | where ResultType != "0" | summarize count() by UserPrincipalName, ResultDescription | order by count_ desc | take 20`
c. Check ThreatIntelligenceIndicator for the IP
d. Verify the user account exists in the tenant:
   `IdentityInfo | where AccountUPN has "<user>" | project AccountUPN, IsAccountEnabled | take 1`

### Azure Resource alerts
a. Check AzureActivity for the resource:
   `AzureActivity | where ResourceGroup has "<rg>" or Resource has "<resource_name>" | project TimeGenerated, OperationNameValue, Caller, ActivityStatusValue | order by TimeGenerated desc | take 20`
b. If the resource is your Azure AI Foundry / Cognitive Services account used by this triage function — note that alerts may be triggered by the automated triage agent's own activity

## Step 4 — Confidence calibration
Your confidence must match the data you found:
- **High** — multiple corroborating data points, clear pattern
- **Medium** — some data found, plausible but not confirmed
- **Low** — little or no data found, queries returned empty or errors
Never assign High confidence when primary queries returned no results.

## Step 5 — Verdict
- **True Positive (Malicious)** — confirmed malicious activity, escalate to L2 immediately
- **True Positive (Suspicious)** — alert fired on a real anomaly, no confirmed malicious intent yet; recommend monitoring
- **True Positive (No Compromise)** — alert fired correctly on a real threat (e.g. phishing email confirmed), user/system was exposed but no downstream compromise detected; still warrants user notification
- **Benign Positive** — alert fired correctly but activity is fully authorized and expected (e.g. IT admin script, approved software)
- **False Positive** — alert fired on wrong/misidentified activity; recommend rule tuning
- **Undetermined** — insufficient data after widening queries; state exactly what data is missing and how to get it

Key distinctions:
- A confirmed phishing email (score 100) is **True Positive (No Compromise)**, not Benign Positive — the threat was real even if the user wasn't compromised
- "No data found" after retrying with wider timespans = **Undetermined**, not False Positive
- Alert title misidentifies the actual process/file = **False Positive**

## Principles
- **Alert title ≠ ground truth.** Always verify entity names against raw event data.
- **Verdict scope — stay focused on the alert.** If the alert's named process/file/entity is NOT found after thorough investigation, the verdict is **False Positive** for this alert. Do NOT upgrade the verdict to Suspicious because you found unrelated activity on the device. Place unrelated observations in Analyst Notes for L2 to review separately.
- **Known-good security agent processes — never flag these as suspicious:**
  - RUXIMICS.exe, SentinelOneAgentHelper.exe, SentinelAgent — SentinelOne EDR
  - MsSense.exe, MsMpEng.exe, SenseIR.exe — Microsoft Defender for Endpoint (MDE)
  - CsSensorService, csfalconservice — CrowdStrike Falcon
  - CbDefense, CbOsxSensor — Carbon Black
  - Registry key modifications by any of the above are expected and benign
- **Known-good vendor paths are strong FP signals:** `C:\Program Files (x86)\Google\`, `C:\Windows\System32\`, `C:\Program Files\Microsoft\`, Azure-owned domains (*.azurewebsites.net, *.azure.com, *.microsoft.com)
- **Widen before giving up.** If a query returns empty, retry with a longer timespan before concluding no data exists.
- **Score/confidence from the detection system matters.** A score of 100 means the vendor system is certain — weight that.
- **Context matters:** 9am action from known IP ≠ 2am action from foreign IP

## Comment format
---
## 🔍 L1 SOC Triage — [Incident Title]
**Analyst:** Claude SOC Agent (Sonnet) | **Date:** [UTC] | **Confidence:** [Low/Medium/High]

### Summary
[2-3 sentences: what happened, what was found, verdict]

### Key Findings
- ...

### Investigation Steps Taken
1. ...

### Verdict
**[Verdict]**
[Reasoning tied to specific data found, not assumptions]

### Recommended Actions
- [ ] ...

### Analyst Notes
[Notes for L2 / next shift]
---

Call post_sentinel_comment ONCE, only after all investigation is complete."""


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch_tool(name, inputs):
    fn_map = {
        "get_incident": get_incident, "get_incident_alerts": get_incident_alerts,
        "get_incident_entities": get_incident_entities, "get_alert_raw_query": get_alert_raw_query,
        "run_kql_query": run_kql_query, "get_ueba_insights": get_ueba_insights,
        "get_signin_logs": get_signin_logs, "get_audit_logs": get_audit_logs,
        "get_device_timeline": get_device_timeline, "post_sentinel_comment": post_sentinel_comment,
    }
    try:
        fn     = fn_map.get(name)
        result = fn(**inputs) if fn else {"error": f"Unknown tool: {name}"}
    except Exception as e:
        result = {"error": str(e)}
    return json.dumps(result, default=str, indent=2)


# ── Agentic loop (Anthropic) ───────────────────────────────────────────────────

def run_analyst(incident_number):
    messages = [{
        "role":    "user",
        "content": (
            f"Investigate Sentinel incident number {incident_number}. "
            "Perform a full L1 triage and post your analysis as a comment to the incident."
        ),
    }]
    logger.info("Starting investigation of incident #%s", incident_number)

    for round_num in range(1, MAX_TOOL_ROUNDS + 1):
        logger.info("Round %d: calling %s", round_num, MODEL)
        response = _anthropic_client().messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            logger.info("Investigation complete")
            break
        if response.stop_reason != "tool_use":
            logger.warning("Unexpected stop_reason: %s", response.stop_reason)
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            logger.info("Tool: %s %s", block.name, json.dumps(block.input)[:200])
            result = dispatch_tool(block.name, block.input)
            logger.info("Result: %s", result[:300])
            tool_results.append({
                "type": "tool_result", "tool_use_id": block.id, "content": result
            })
            if block.name == "post_sentinel_comment":
                logger.info("Comment posted")
        messages.append({"role": "user", "content": tool_results})
    else:
        logger.warning("Reached max rounds (%d)", MAX_TOOL_ROUNDS)


# ── HTTP trigger ───────────────────────────────────────────────────────────────

@app.route(route="triage", methods=["POST"])
def triage(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    incident_number = body.get("incident_number")
    if not incident_number:
        return func.HttpResponse("Missing incident_number", status_code=400)

    try:
        run_analyst(int(incident_number))
        return func.HttpResponse(
            json.dumps({"status": "ok", "incident_number": incident_number}),
            mimetype="application/json", status_code=200)
    except Exception as e:
        logger.exception("Triage failed")
        return func.HttpResponse(
            json.dumps({"status": "error", "message": str(e)}),
            mimetype="application/json", status_code=500)
