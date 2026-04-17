# PostureIQ — Enhancement Backlog

> Living document tracking planned enhancements, feature ideas, and architectural evolution.
> Last updated: 2026-04-15

---

## Status Legend

| Status | Meaning |
|--------|---------|
| ✅ Shipped | Implemented and deployed |
| 🔄 In Progress | Currently being developed |
| 📋 Planned | Approved for future work |
| 💡 Idea | Under consideration, needs design |

---

## v45 — Multi-Hop Attack Path Analysis (Shipped)

**Status:** ✅ Shipped (2026-04-15)

Deepened PostureIQ `attack_paths.py` with 5 new multi-hop detection categories using existing collected evidence (zero new collectors required).

| # | Detection | Type | Evidence Used | Risk Score |
|---|-----------|------|---------------|------------|
| 1 | Key Vault → Identity → Resource chain | `credential_chain / keyvault_to_resource` | `azure-keyvault`, `azure-role-assignment` | 88 (High) |
| 2 | App/Function → Managed Identity → Privileged Resource | `lateral_movement / app_mi_to_resource` | `azure-webapp-config`, `azure-function-app`, `azure-role-assignment` | 87 (High) |
| 3 | Conditional Access bypass — privileged roles without MFA | `ca_bypass / privileged_role_no_mfa` | `entra-conditional-access-policy`, `entra-role-assignment` | 92 (Critical) |
| 4 | Service Principal with weak credentials + privileged role | `credential_chain / weak_credential_privileged_sp` | `entra-application`, `entra-service-principal`, `azure-role-assignment` | 75–82 (Medium–High) |
| 5 | Network pivot — Internet-exposed VM with privileged MI | `network_pivot / internet_exposed_vm_privileged_mi` | `azure-nsg-rule`, `azure-vm-config`, `azure-role-assignment` | 93 (Critical) |

**Query support:** Users can ask about specific categories: "credential chain", "CA bypass", "network pivot", "managed identity chain", "keyvault chain".

---

## Backlog — Option B: Standalone Attack Pathfinder Tool (Azure-Only, Multi-Cloud Architected)

**Status:** 📋 Planned  
**Priority:** Medium  
**Effort:** 3–5 sessions  
**Prerequisite:** v45 shipped ✅

### Concept

A new agent tool `run_attack_pathfinder` that performs deep graph-based attack path analysis. Initially Azure-only but architectured with a provider abstraction layer to support AWS/GCP in the future.

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Attack Pathfinder Tool               │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Azure    │  │ AWS      │  │ GCP      │       │
│  │ Provider │  │ Provider │  │ Provider │       │
│  │ (v1)  ✅ │  │ (future) │  │ (future) │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │             │
│       ▼              ▼              ▼             │
│  ┌─────────────────────────────────────┐         │
│  │     Unified Knowledge Graph          │         │
│  │  (Nodes: identities, resources,     │         │
│  │   networks, credentials)            │         │
│  │  (Edges: trust, access, network,    │         │
│  │   credential-sharing)               │         │
│  └──────────────┬──────────────────────┘         │
│                 │                                  │
│       ┌─────────▼──────────┐                      │
│       │  Graph Traversal   │                      │
│       │  Engine (BFS/DFS   │                      │
│       │  with attack       │                      │
│       │  semantics)        │                      │
│       └─────────┬──────────┘                      │
│                 │                                  │
│       ┌─────────▼──────────┐                      │
│       │  LLM Reasoning     │                      │
│       │  Layer (attacker   │                      │
│       │  simulation)       │                      │
│       └─────────┬──────────┘                      │
│                 │                                  │
│       ┌─────────▼──────────┐                      │
│       │  Path Report +     │                      │
│       │  Remediation       │                      │
│       └────────────────────┘                      │
└─────────────────────────────────────────────────┘
```

### Components to Build

| Component | Description | Estimated Lines |
|-----------|-------------|-----------------|
| `attack_pathfinder.py` | Orchestrator + tool registration | ~100 |
| `graph_model.py` | Unified knowledge graph (nodes, edges, trust/access/network types) | ~500 |
| `graph_traversal.py` | BFS/DFS attack path traversal with multi-hop semantics | ~400 |
| `llm_reasoning.py` | LLM-powered attacker simulation prompts | ~300 |
| `providers/azure_provider.py` | Azure evidence → graph node/edge mapping | ~300 |
| `providers/base_provider.py` | Abstract provider interface | ~50 |
| Config extension | New `pathfinder` section in config schema | ~50 |
| Agent tool definition | `run_attack_pathfinder` tool in agent.py | ~100 |
| **Total** | | **~1800** |

### New Detection Capabilities (beyond v45)

1. **Multi-hop traversal (3+ hops)**: A → B → C → D chains where no single hop is critical but the chain is
2. **Cross-subscription pivots**: Identity in sub-A with role in sub-B that trusts sub-C
3. **VNet peering chains**: VNet A ↔ VNet B ↔ VNet C creating network adjacency across subscriptions
4. **Private Endpoint bypass**: Resource with private endpoint but identity has both network AND data-plane access
5. **App Registration → Service Principal → MI → Resource**: Full 4-hop identity chain
6. **LLM attacker reasoning**: "Given this graph, what would an APT actor target first?"

### Data Flow

1. Reuse PostureIQ evidence (no re-collection) OR collect on demand
2. Build in-memory graph from evidence index
3. Run deterministic traversal for known patterns
4. Run LLM reasoning for novel/emergent patterns
5. Merge, deduplicate, score, rank
6. Output: structured paths + narrative + remediation scripts

---

## Backlog — Option C: Full Cross-Cloud Attack Pathfinder AI

**Status:** 💡 Idea  
**Priority:** Low  
**Effort:** 10+ sessions  
**Prerequisite:** Option B completed

### Vision

An AI agent that maps potential attack paths spanning Azure, AWS, and GCP, discovering cross-cloud breach pathways like S3 credentials leading to Azure subscription access.

### Why It's a Separate Product-Level Effort

| Requirement | Gap | Effort |
|-------------|-----|--------|
| **AWS Collectors** | Zero exist. Need boto3, STS/AssumeRole auth, IAM/S3/EC2/RDS/Lambda collection | ~2000+ lines |
| **GCP Collectors** | Zero exist. Need google-cloud SDK, GCP IAM, GCS/GKE/Cloud SQL collection | ~1500+ lines |
| **Cross-Cloud Auth** | Current auth is Azure AD only. Need AWS STS, GCP service accounts, credential management | ~500 lines |
| **Cross-Cloud Graph** | Trust relationships spanning clouds (e.g., Azure AD trust → AWS IAM role, GCP Workload Identity → Azure) | ~600 lines |
| **Continuous Monitoring** | PostureIQ is on-demand. Continuous needs event-driven architecture (webhooks, change feeds, scheduled triggers) | Architecture change |
| **Cross-Cloud Remediation** | Fix scripts need AWS CLI, gcloud CLI, multi-cloud Terraform | ~800 lines |
| **Testing** | Need AWS + GCP test tenants/accounts | Infrastructure |
| **Total New Code** | | **~5000+ lines** |

### Cross-Cloud Attack Patterns to Detect

1. **S3 credential leak → Azure pivot**: AWS S3 bucket with public access contains Azure service principal credentials → full Azure subscription access
2. **Azure AD trust → AWS IAM assume-role**: Azure AD identity trusted by AWS IAM role → cross-cloud lateral movement
3. **GCP Workload Identity → Azure managed identity**: GCP service linked to Azure MI → cloud-to-cloud pivot
4. **Shared VPN/ExpressRoute**: Network paths connecting cloud VPCs/VNets enabling lateral movement
5. **DNS exfiltration chains**: Compromised DNS in one cloud resolving to resources in another
6. **Container registry poisoning**: ACR/ECR/GCR image shared across clouds → supply chain attack path
7. **Shared secrets in Key Vault/Secrets Manager/Secret Manager**: Same credentials stored across cloud vaults

### Architecture Requirements

- **Provider abstraction**: Each cloud implements `CloudProvider` interface with `collect()`, `build_graph()`, `get_remediation()`
- **Unified identity model**: Map Azure AD, AWS IAM, GCP IAM to a common identity schema
- **Graph database option**: For large environments, consider Neo4j or in-memory NetworkX vs. simple dict-based graph
- **Scheduled execution**: Azure Functions timer trigger or Container App job for continuous scanning
- **Dashboard integration**: Results feed into the web SPA with interactive graph visualization (d3-force or cytoscape.js)

---

## Backlog — Other Enhancements

### Attack Path Visualization (Sequence Diagrams)

**Status:** 💡 Idea  
**Priority:** Low  
**Effort:** 1–2 sessions

Generate animated Mermaid sequence diagrams for each attack path category using existing `seq-engine.js`. Embed in PostureIQ HTML report.

### Continuous PostureIQ Monitoring

**Status:** 💡 Idea  
**Priority:** Low  

Scheduled re-runs with delta comparison, alerting on new critical attack paths or score degradation.

### PostureIQ Drift Alerting

**Status:** 💡 Idea  
**Priority:** Low  

Webhook/email notification when PostureIQ score drops below threshold or new critical paths appear.

---

## Revision History

| Date | Change |
|------|--------|
| 2026-04-15 | Initial backlog created. v45 shipped (multi-hop attack paths). Option B & C documented. |
