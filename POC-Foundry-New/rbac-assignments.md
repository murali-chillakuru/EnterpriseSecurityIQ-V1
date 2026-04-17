# RBAC Assignments — ESIQNew

> All roles assigned to **ESIQNew-identity** (principal ID: `d742617c-6f14-4215-be65-e1f7b68866de`).

## Role Assignments

| # | Role | Scope | Purpose |
|---|---|---|---|
| 1 | **AcrPull** | `esiqnewacr` (Container Registry) | Pull container images during deployment |
| 2 | **Reader** | Subscription (`d33fc1a7-...`) | Read Azure resource metadata for security assessments |
| 3 | **Security Reader** | Subscription (`d33fc1a7-...`) | Read Microsoft Defender for Cloud findings and security policies |
| 4 | **Cognitive Services OpenAI User** | `ESIQNew-AI` (AI Services) | Call gpt-4.1 and gpt-5.1 model deployments |
| 5 | **Azure AI Developer** | `ESIQNew-AI` (Foundry Resource) | Access Foundry Resource and child Project |
| 6 | **Storage Blob Data Contributor** | `esiqnewstorage` (Storage Account) | Upload, download, and list report blobs for persistent storage |

## Identity Details

| Property | Value |
|---|---|
| Name | `ESIQNew-identity` |
| Type | User-assigned managed identity |
| Principal ID | `d742617c-6f14-4215-be65-e1f7b68866de` |
| Client ID | `d5d10273-4a8b-4251-9b9d-00fe035df97a` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ESIQNew-identity` |

## Role Definition IDs

| Role | Built-in Role ID |
|---|---|
| AcrPull | `7f951dda-4ed3-4680-a7ca-43fe172d538d` |
| Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` |
| Security Reader | `39bc4728-0917-49c7-9d2c-d95423bc2eb4` |
| Cognitive Services OpenAI User | `5e0bd9bd-7b93-4f28-af87-19fc36ad61bd` |
| Azure AI Developer | `64702f94-c441-49e6-a78b-ef80e0188fee` |
| Storage Blob Data Contributor | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` |

## Least-Privilege Notes

- **Reader** + **Security Reader** are required at subscription scope for the agent to enumerate resources and Defender findings across the tenant.
- **Cognitive Services OpenAI User** (not Contributor) ensures the identity can only invoke models, not manage deployments.
- **AcrPull** is scoped to the specific registry, not the resource group.
- **Azure AI Developer** grants access to the Foundry Resource and all child Projects (including ESIQNew-project).
- **Storage Blob Data Contributor** is scoped to the specific storage account for persistent report storage via Azure Blob (added in v25).
