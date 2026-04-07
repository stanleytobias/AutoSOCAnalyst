# AutoSOCAnalyst
# SOC Analyst Agent — Azure Function (Claude Sonnet)

An automated Level 1 SOC triage agent that investigates Microsoft Sentinel incidents using Claude Sonnet via Azure AI Foundry. When triggered, it pulls incident details, runs KQL queries against Log Analytics, and posts a structured triage report as a comment directly on the Sentinel incident.

## How it works

1. You POST an incident number to the function's HTTP endpoint
2. The agent calls Claude Sonnet, which uses a set of tools to investigate:
   - Fetch the incident, its alerts, and its entities from Sentinel
   - Run KQL queries against Log Analytics (sign-in logs, audit logs, device events, UEBA, threat intel)
3. Claude determines a verdict (True Positive, False Positive, Benign Positive, etc.)
4. The agent posts a formatted triage report as a comment on the Sentinel incident

## Prerequisites

Before deploying, you need:

- An **Azure subscription** with Microsoft Sentinel enabled
- A **Log Analytics workspace** connected to Sentinel
- An **Azure AI Foundry** resource with a Claude Sonnet deployment
- An **Azure Function App** (Python 3.11+) with a system-assigned Managed Identity enabled
- Python 3.11+ and the [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local) installed locally (for local dev/deployment)

---

## Step 1 — Deploy a Claude model in Azure AI Foundry

1. Go to [Azure AI Foundry](https://ai.azure.com) and open your project.
2. Navigate to **Models + endpoints** > **Deploy model**.
3. Select **Claude Sonnet** (claude-sonnet-4-6 or later) from the Anthropic catalog.
4. Name the deployment — by default this code expects the name `SOC-Automation-claude-sonnet-4-6`.
   If you use a different name, update the `MODEL` constant in `function_app.py` (line 34).
5. Once deployed, copy:
   - The **endpoint URL** (e.g. `https://<your-resource>.services.ai.azure.com/anthropic`)
   - An **API key** from the Keys & Endpoint section

---

## Step 2 — Assign RBAC roles to the Function App's Managed Identity

The function uses its Managed Identity to authenticate to Azure — no service principal or credentials needed in production.

In the Azure Portal, go to each resource below and add a role assignment for your Function App's identity:

| Resource | Role to assign |
|----------|---------------|
| Your Sentinel workspace (Microsoft Sentinel) | **Microsoft Sentinel Responder** |
| Your Log Analytics workspace | **Log Analytics Reader** |
| Your Azure AI Foundry resource | **Cognitive Services OpenAI User** |

> **How to assign:** Resource → Access control (IAM) → Add role assignment → Search for the role → Assign to your Function App (type: Managed Identity).

---

## Step 3 — Configure environment variables

### For local development

Copy `local.settings.json.example` to `local.settings.json` and fill in your values:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "FOUNDRY_API_KEY": "<your-azure-ai-foundry-api-key>",
    "FOUNDRY_ENDPOINT": "https://<your-resource>.services.ai.azure.com/anthropic",
    "SUBSCRIPTION_ID": "<your-azure-subscription-id>",
    "RESOURCE_GROUP": "<your-resource-group-name>",
    "WORKSPACE_NAME": "<your-log-analytics-workspace-name>",
    "WORKSPACE_ID": "<your-log-analytics-workspace-id>",
    "ORGANIZATION_NAME": "<your-organization-name>"
  }
}
```

> `local.settings.json` is in `.gitignore` — never commit it.

### For production (Azure Function App)

Set these as **Application Settings** in your Function App:

| Setting | Description |
|---------|-------------|
| `FOUNDRY_API_KEY` | API key from your Azure AI Foundry resource |
| `FOUNDRY_ENDPOINT` | Endpoint URL of your AI Foundry resource (no trailing `/v1`) |
| `SUBSCRIPTION_ID` | Your Azure Subscription ID (GUID) |
| `RESOURCE_GROUP` | Resource group containing your Sentinel workspace |
| `WORKSPACE_NAME` | Name of your Log Analytics / Sentinel workspace |
| `WORKSPACE_ID` | GUID of your Log Analytics workspace |
| `ORGANIZATION_NAME` | Your company name — appears in the triage report header |

> In the Portal: Function App → Settings → Environment variables → Add each key/value.

---

## Step 4 — Install dependencies and deploy

```bash
# Install dependencies locally
pip install -r requirements.txt

# Run locally (requires Azurite or a real storage account)
func start

# Deploy to Azure
func azure functionapp publish <your-function-app-name>
```

---

## Step 5 — Trigger a triage

The function exposes a single HTTP endpoint:

```
POST https://<your-function-app>.azurewebsites.net/api/triage
x-functions-key: <your-function-key>
Content-Type: application/json

{
  "incident_number": 12345
}
```

The incident number is the number shown in the Sentinel incident list (not the GUID). The function will return `{"status": "ok"}` immediately — the triage runs and posts to the incident asynchronously within the 10-minute timeout.

### Automating via Sentinel Automation Rules

To trigger this automatically when a new incident is created:

1. In Sentinel, go to **Automation** > **Create** > **Automation rule**
2. Set trigger: **When incident is created**
3. Action: **Run playbook** — create a Logic App playbook that calls this function with the incident number
4. Alternatively, use a **Webhook** action if your tier supports it

---

## Customisation

| What | Where |
|------|-------|
| Change the Claude model | `MODEL` constant — `function_app.py` line 34 |
| Increase tool call limit | `MAX_TOOL_ROUNDS` — `function_app.py` line 36 |
| Extend the function timeout | `functionTimeout` in `host.json` (max 60 min on Premium/Dedicated plan) |
| Modify triage instructions | `SYSTEM_PROMPT` in `function_app.py` |
| Add new investigation tools | Add a function + entry in `TOOLS` + entry in `dispatch_tool()` |

---

## Required Azure resources (summary)

```
Azure Subscription
├── Resource Group
│   ├── Log Analytics Workspace  ← Sentinel data lives here
│   │   └── Microsoft Sentinel
│   ├── Azure AI Foundry         ← Claude model deployment
│   └── Function App             ← This code
│       └── Managed Identity     ← Needs the 3 roles above
```

---

## Security notes

- `local.settings.json` is excluded from version control — add it to `.gitignore` if not already present
- In production, the function uses Managed Identity — `FOUNDRY_API_KEY` is only needed for local development or if your Foundry resource requires key auth
- The HTTP endpoint requires a function key (`AuthLevel.FUNCTION`) — keep this key secret
- Review the RBAC roles carefully: **Sentinel Responder** allows the agent to post comments; it does not allow closing or modifying incidents
