# SOC Multi-Agent Architecture Design
## Pre-Triage & Cross-Platform Entity Enrichment

---

## 1. Executive Summary

This document defines the architecture for a **multi-agent SOC system** that performs automated pre-triage on Microsoft Sentinel incidents. The system extracts entities from incidents, fans out investigations across multiple security tools (Sentinel, Prisma CSPM, Cyfirma, Cisco NBAD, CrowdStrike), aggregates findings, and produces a triage verdict.

**Key architectural decisions:**
- **Manager Agent**: Azure AI Foundry Agent Service (orchestration, routing, aggregation)
- **Sub-Agents**: GitHub Copilot-powered agents with MCP tool access (replacing Security Copilot per customer preference)
- **Integration Layer**: MCP (Model Context Protocol) servers wrapping each external tool's REST API

---

## 2. Architecture Layers

### Layer 1: Trigger Layer
| Component | Technology | Purpose |
|-----------|-----------|---------|
| Sentinel Incident Webhook | Azure Logic App / Automation Rule | Fires on incident creation, extracts entities, invokes Manager Agent |

### Layer 2: Orchestration Layer (Manager Agent)
| Component | Technology | Purpose |
|-----------|-----------|---------|
| Manager Agent | Azure AI Foundry Agent Service | Parses entities, decides routing, fans out to sub-agents, aggregates results |
| Entity Router | Foundry tool/function | Maps entity types to sub-agent invocations |
| Result Aggregator | Foundry tool/function | Correlates findings, generates triage verdict |

### Layer 3: Investigation Layer (Sub-Agents)
| Sub-Agent | Scope | MCP Server Used |
|-----------|-------|----------------|
| Sentinel Analyst Agent | KQL queries, alert correlation, incident history | Sentinel MCP Server |
| Cloud Security Agent | Cloud misconfigurations, IAM findings, compliance | Prisma CSPM MCP Server |
| Threat Intelligence Agent | IOC enrichment, threat actor attribution, campaign mapping | Cyfirma MCP Server |
| Network Security Agent | Network anomalies, flow analysis, behavioral detection | Cisco NBAD MCP Server |
| EDR Agent | Endpoint detections, process trees, lateral movement | CrowdStrike MCP Server |

### Layer 4: Integration Layer (MCP Servers)
| MCP Server | Wraps | Auth Method | Hosting |
|------------|-------|-------------|---------|
| Sentinel MCP Server | Log Analytics API + Sentinel REST API | Azure AD (OAuth2 / Managed Identity) | Azure Container Apps |
| Prisma CSPM MCP Server | Prisma Cloud REST API v2 | Access Key + Secret Key | Azure Container Apps |
| Cyfirma MCP Server | DeCYFIR REST API | API Key / Bearer Token | Azure Container Apps |
| Cisco NBAD MCP Server | Secure Network Analytics REST API | Username/Password + XSRF Token | Azure Container Apps |
| CrowdStrike MCP Server | Falcon API (OAuth2) | Client ID + Client Secret | Azure Container Apps |

---

## 3. Manager Agent - How It Decides Which Sub-Agent to Call

The Manager Agent uses a **two-phase routing strategy**:

### Phase 1: Entity-Type Based Routing

| Entity Type | Sentinel | Prisma CSPM | Cyfirma | Cisco NBAD | CrowdStrike |
|-------------|:--------:|:-----------:|:-------:|:----------:|:-----------:|
| **IP Address** | ✅ | | ✅ | ✅ | |
| **Hostname/Device** | ✅ | ✅ | | | ✅ |
| **User/Account** | ✅ | ✅ | | | |
| **URL/Domain** | ✅ | | ✅ | | |
| **File Hash** | ✅ | | ✅ | | ✅ |
| **Cloud Resource** | ✅ | ✅ | | | |

### Phase 2: Alert-Source Metadata Routing

Since external tools (Prisma, Cyfirma, Cisco NBAD) send **alerts only** (no telemetry) to Sentinel, the Manager Agent inspects the `ProductName` or `ProviderName` field:

```
IF alert.ProductName == "Prisma Cloud" → also invoke Cloud Security Agent
IF alert.ProductName == "Cyfirma"      → also invoke Threat Intel Agent  
IF alert.ProductName == "Cisco NBAD"   → also invoke Network Security Agent
```

### Implementation: Manager Agent System Prompt (Foundry)

```
You are a SOC Manager Agent. When an incident arrives:

1. Extract all entities (IPs, Users, Hosts, URLs, FileHashes, CloudResources)
2. For each entity, determine which sub-agents to invoke using the routing matrix
3. Also check the alert source - if the alert originated from an external tool, 
   always invoke that tool's corresponding sub-agent for deeper context
4. Fan out investigations in parallel to all relevant sub-agents
5. Collect all results and produce a unified triage report with:
   - Severity assessment (Critical/High/Medium/Low/Informational)
   - Correlated findings across tools
   - Recommended response actions
   - Confidence score
```

---

## 4. Interaction Flow - Detailed

### 4.1 Manager ↔ Sub-Agent Interaction

```
Manager Agent (Foundry)
    │
    ├─ Uses Azure AI Foundry's "Agent-to-Agent" calling pattern
    │  (Foundry supports multi-agent orchestration natively)
    │
    ├─ Each Sub-Agent is defined as a GitHub Copilot agent with:
    │   ├─ A system prompt scoped to its security domain
    │   ├─ MCP server connections for tool access
    │   └─ Structured output schema for consistent result format
    │
    └─ Communication: Foundry sends a structured task to each sub-agent
       containing the entity, context, and expected output format
```

### 4.2 Sub-Agent ↔ MCP Server Interaction

```
GitHub Copilot Sub-Agent
    │
    ├─ Receives task: "Investigate IP 10.0.0.5 for threat intelligence"
    │
    ├─ Reasons about which MCP tools to call:
    │   ├─ lookup_ioc(indicator="10.0.0.5", type="ip")
    │   ├─ get_threat_campaigns(indicator="10.0.0.5")
    │   └─ check_attribution(indicator="10.0.0.5")
    │
    ├─ MCP Protocol handles:
    │   ├─ Tool discovery (listTools)
    │   ├─ Tool invocation (callTool)
    │   └─ Result return (structured JSON)
    │
    └─ Sub-agent synthesizes results into a finding report
```

### 4.3 MCP Server ↔ External Tool Interaction

```
MCP Server (e.g., Prisma CSPM MCP)
    │
    ├─ Receives MCP tool call: get_cloud_alerts(resourceId="...")
    │
    ├─ Translates to REST API call:
    │   POST https://api.prismacloud.io/v2/alert
    │   Headers: { "x-redlock-auth": "<JWT_TOKEN>" }
    │   Body: { "filters": [{"name":"cloud.resourceId","value":"..."}] }
    │
    ├─ Handles authentication:
    │   ├─ Token refresh if expired
    │   ├─ Credential retrieval from Azure Key Vault
    │   └─ Rate limiting / retry logic
    │
    └─ Returns normalized MCP response to sub-agent
```

---

## 5. MCP vs API Integration - Tool Support Analysis

### MCP Support Status Per Tool

| Tool | Native MCP Server | Community MCP Server | Integration Approach |
|------|:-----------------:|:-------------------:|---------------------|
| **Microsoft Sentinel** | ❌ No | ✅ Yes ([ms-sentinel-mcp-server](https://github.com/dstreefkerk/ms-sentinel-mcp-server), [azure-sentinel-mcp](https://github.com/jmstar85/azure-sentinel-mcp)) | Use community MCP server or build custom. Wraps Log Analytics REST API + Sentinel API. KQL query execution via API. |
| **Palo Alto Prisma Cloud (CSPM)** | ❌ No | ❌ No (only a docs server exists) | **Custom MCP server required.** Wrap Prisma Cloud CSPM REST API v2. Auth: Access Key/Secret → JWT token exchange. |
| **Cyfirma (DeCYFIR)** | ❌ No | ❌ No | **Custom MCP server required.** Wrap Cyfirma DeCYFIR REST API. Auth: API Key in header. |
| **Cisco NBAD (Secure Network Analytics)** | ❌ No | ❌ No | **Custom MCP server required.** Wrap Cisco Secure Network Analytics REST API (formerly Stealthwatch). Auth: Session-based with XSRF tokens. |
| **CrowdStrike Falcon** | ✅ Yes ([CrowdStrike/aidr-mcp-server](https://github.com/CrowdStrike/aidr-mcp-server)) | ✅ Yes ([cs-ngsiem-mcp](https://github.com/rodkinal/cs-ngsiem-mcp), LogScale MCP) | Use official AIDR MCP server. Also community NGSIEM MCP available. Auth: OAuth2 Client Credentials. |

### Recommendation

| Tool | Recommendation |
|------|---------------|
| **Sentinel** | Start with community `ms-sentinel-mcp-server`. Extend with custom KQL tools as needed. |
| **Prisma Cloud** | Build custom MCP server. Use Python MCP SDK + `requests`. Estimated 5-7 tools (alerts, compliance, assets, IAM). |
| **Cyfirma** | Build custom MCP server. Use Python MCP SDK. Estimated 3-5 tools (IOC lookup, campaign intel, vulnerability intel). |
| **Cisco NBAD** | Build custom MCP server. Use Python MCP SDK. Estimated 4-6 tools (flow queries, anomaly detection, host groups, policies). |
| **CrowdStrike** | Use official `CrowdStrike/aidr-mcp-server`. Supplement with NGSIEM MCP if LogScale queries are needed. |

---

## 6. Custom MCP Server Design Pattern

For tools requiring custom MCP servers (Prisma, Cyfirma, Cisco NBAD), follow this pattern:

```python
# Example: Prisma Cloud CSPM MCP Server (Python)
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("prisma-cspm-mcp")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="get_cloud_alerts",
            description="Get Prisma Cloud alerts for a resource or IP",
            inputSchema={
                "type": "object",
                "properties": {
                    "resource_id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high","medium","low"]},
                    "time_range": {"type": "integer", "description": "Hours to look back"}
                }
            }
        ),
        Tool(
            name="get_compliance_posture",
            description="Get compliance posture for a cloud account or resource",
            inputSchema={...}
        ),
        Tool(
            name="get_iam_findings",
            description="Get IAM-related findings for a user or role",
            inputSchema={...}
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "get_cloud_alerts":
        # Auth: retrieve credentials from Azure Key Vault
        # Call: POST https://api.prismacloud.io/v2/alert
        # Return: normalized results
        ...
```

### MCP Server Hosting

All MCP servers should be hosted on **Azure Container Apps** with:
- **Azure Key Vault** for credential storage (API keys, secrets)
- **Managed Identity** for Sentinel (no credentials needed)
- **Streamable HTTP transport** for remote MCP connectivity
- **Health checks** and **auto-scaling** per server

---

## 7. GitHub Copilot as Sub-Agent Runtime

Since the customer prefers GitHub Copilot over Security Copilot, here's how GHCP fits:

### Option A: GitHub Copilot Extensions (Recommended)
- Build each sub-agent as a **GitHub Copilot Extension** (Skillset or Agent type)
- Each extension connects to its MCP server(s)
- The Foundry Manager Agent invokes these via the **Copilot Extensions API**
- Pros: Native MCP support in VS Code/GHCP, extensible, marketplace potential
- Cons: Currently oriented toward developer workflows; SOC use may require adaptation

### Option B: GitHub Models + MCP (Programmatic)
- Use **GitHub Models** (Azure AI-backed) as the LLM backbone for sub-agents
- Build sub-agents as standalone services that use GitHub Models API + MCP SDK
- Manager Agent calls sub-agents via REST endpoints
- Pros: Full programmatic control, no UI dependency
- Cons: Not using GHCP directly; more of a "powered by GitHub Models" approach

### Option C: Hybrid - Foundry Agents with GitHub Models Backend
- Use **Azure AI Foundry Agent Service** for all agents (manager + sub)
- Configure sub-agents to use **GitHub Models** (GPT-4o, etc.) as the model provider
- Each sub-agent has MCP server connections defined in Foundry
- Pros: Unified orchestration, native multi-agent support, GitHub model quality
- Cons: Less "GitHub Copilot branded" but architecturally cleanest

### Recommendation: **Option C** for production, **Option A** for analyst-facing interactive use

---

## 8. Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Azure Subscription                        │
│                                                              │
│  ┌──────────────┐    ┌───────────────────────────────────┐  │
│  │ Sentinel      │───▶│ Logic App / Automation Rule       │  │
│  │ Incident      │    │ (Trigger on incident creation)    │  │
│  └──────────────┘    └──────────┬────────────────────────┘  │
│                                  │                           │
│                                  ▼                           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           Azure AI Foundry Agent Service               │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │ Manager Agent (GPT-4o via GitHub Models)        │  │  │
│  │  │  - Entity parser tool                           │  │  │
│  │  │  - Sub-agent invoker tool                       │  │  │
│  │  │  - Result aggregator tool                       │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │  │
│  │  │Sentinel  │ │Cloud Sec │ │Threat    │ │Network   │ │  │
│  │  │Analyst   │ │Agent     │ │Intel     │ │Security  │ │  │
│  │  │Agent     │ │          │ │Agent     │ │Agent     │ │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │  │
│  └───────┼─────────────┼────────────┼────────────┼───────┘  │
│          │             │            │            │           │
│          ▼             ▼            ▼            ▼           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Azure Container Apps (MCP Servers)        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │  │
│  │  │Sentinel  │ │Prisma    │ │Cyfirma   │ │Cisco     │ │  │
│  │  │MCP       │ │CSPM MCP  │ │MCP       │ │NBAD MCP  │ │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │  │
│  └───────┼─────────────┼────────────┼────────────┼───────┘  │
│          │             │            │            │           │
│  ┌───────▼─────────────────────────────────────────────┐    │
│  │              Azure Key Vault                         │    │
│  │  (API keys, secrets, certificates for all tools)     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
          │             │            │            │
          ▼             ▼            ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │Sentinel  │ │Prisma    │ │Cyfirma   │ │Cisco     │
    │Log       │ │Cloud     │ │DeCYFIR   │ │Secure    │
    │Analytics │ │API       │ │API       │ │Network   │
    │API       │ │          │ │          │ │Analytics │
    └──────────┘ └──────────┘ └──────────┘ └──────────┘
```

---

## 9. Key Design Pointers & Considerations

### 9.1 Security
- **All credentials** in Azure Key Vault, never hardcoded in MCP servers
- **Managed Identity** for Sentinel access (zero-credential)
- **Network isolation**: MCP servers in private VNet with service endpoints
- **Audit logging**: All agent decisions and API calls logged to Log Analytics
- **Least privilege**: Each MCP server's identity has minimal RBAC roles

### 9.2 Performance
- **Parallel fan-out**: Manager invokes all relevant sub-agents simultaneously
- **Timeout handling**: Each sub-agent has a 30-60s timeout; partial results are acceptable
- **Caching**: Frequently queried IOCs cached in Redis (TTL: 1 hour for threat intel)
- **Rate limiting**: MCP servers implement per-tool rate limiting to avoid API throttling

### 9.3 Reliability
- **Graceful degradation**: If one sub-agent fails, others still contribute to triage
- **Retry with backoff**: MCP servers retry transient API failures (429, 503)
- **Circuit breaker**: Disable a sub-agent if its tool is consistently unavailable
- **Dead letter queue**: Failed investigations queued for manual analyst review

### 9.4 Observability
- **Application Insights** on all MCP servers and Foundry agents
- **Correlation IDs** passed from incident → manager → sub-agents → MCP calls
- **Dashboard**: Triage outcomes, tool response times, failure rates, entity coverage

### 9.5 Cost Optimization
- **GitHub Models**: Use GPT-4o-mini for routine lookups, GPT-4o for complex correlation
- **Container Apps**: Scale-to-zero for MCP servers during low-incident periods
- **Token budgets**: Set max token limits per sub-agent investigation

---

## 10. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-3)
- [ ] Set up Azure AI Foundry workspace with Manager Agent
- [ ] Deploy Sentinel MCP server (community) on Container Apps
- [ ] Build Manager Agent with entity extraction and Sentinel-only routing
- [ ] End-to-end test: Incident → Manager → Sentinel Analyst → Triage Report

### Phase 2: External Integrations (Weeks 4-7)
- [ ] Build custom Prisma CSPM MCP server (Python MCP SDK)
- [ ] Build custom Cyfirma MCP server
- [ ] Build custom Cisco NBAD MCP server
- [ ] Deploy CrowdStrike official AIDR MCP server
- [ ] Integrate all MCP servers with sub-agents

### Phase 3: Intelligence & Optimization (Weeks 8-10)
- [ ] Implement correlation logic in Manager Agent (cross-tool finding correlation)
- [ ] Add confidence scoring and severity calculation
- [ ] Build automated response recommendations
- [ ] Set up observability dashboard

### Phase 4: Production Hardening (Weeks 11-12)
- [ ] Security review (credential management, network isolation)
- [ ] Load testing and performance tuning
- [ ] Runbook for operations team
- [ ] Analyst feedback loop integration

---

## 11. API Reference Summary

### Prisma Cloud CSPM API
- **Base URL**: `https://api<N>.prismacloud.io` (region-specific)
- **Auth**: `POST /login` with Access Key + Secret Key → JWT token
- **Key Endpoints**: 
  - `GET /v2/alert` - List alerts
  - `GET /compliance/posture` - Compliance posture
  - `GET /iam` - IAM findings
  - `GET /resource` - Cloud resource inventory

### Cyfirma DeCYFIR API
- **Base URL**: `https://decyfir.cyfirma.com/api/v1`
- **Auth**: API Key in `Authorization` header
- **Key Endpoints**:
  - `GET /ioc/search` - IOC lookup (IP, domain, hash)
  - `GET /campaigns` - Threat campaigns
  - `GET /vulnerability` - Vulnerability intelligence

### Cisco Secure Network Analytics (NBAD) API
- **Base URL**: `https://<smc-host>/token/v2/authenticate`
- **Auth**: Session cookie + XSRF token (POST credentials → session)
- **Key Endpoints**:
  - `GET /sw-reporting/v2/tenants/{tenantId}/flows/queries` - Flow queries
  - `GET /sw-reporting/v2/tenants/{tenantId}/security-events` - Security events
  - `GET /smc-configuration/rest/v1/tenants/{tenantId}/hosts` - Host details

### CrowdStrike Falcon API
- **Base URL**: `https://api.crowdstrike.com`
- **Auth**: OAuth2 Client Credentials → Bearer token
- **Key Endpoints**:
  - `GET /detects/queries/detects/v1` - Detection queries
  - `GET /incidents/queries/incidents/v1` - Incidents
  - `POST /intel/entities/indicators/GET/v1` - Threat intel indicators

### Microsoft Sentinel / Log Analytics API
- **Base URL**: `https://api.loganalytics.io/v1/workspaces/{workspaceId}`
- **Auth**: Azure AD OAuth2 (Managed Identity recommended)
- **Key Endpoints**:
  - `POST /query` - Execute KQL query
  - `GET /providers/Microsoft.SecurityInsights/incidents` - List incidents
  - `GET /providers/Microsoft.SecurityInsights/alertRules` - Alert rules
