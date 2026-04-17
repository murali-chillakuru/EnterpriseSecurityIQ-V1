# EnterpriseSecurityIQ — Web Dashboard

**Author:** Murali Chillakuru

A single-page web application for interacting with the EnterpriseSecurityIQ agent through a browser. Provides a visual interface for running assessments, viewing results, and querying the agent.

## Features

- **SSO Authentication** — Microsoft Entra ID (Azure AD) sign-in via MSAL.js
- **Assessment Runner** — Select frameworks and scopes, launch assessments with real-time progress
- **Results Viewer** — View findings by domain/severity/status with filtering and search
- **Agent Chat** — Natural-language interaction with the Foundry-hosted agent
- **Dark / Light Theme** — Automatic theme detection with manual toggle

## Prerequisites

- A deployed EnterpriseSecurityIQ agent (see [Deployment Guide](../docs/deployment-guide.md))
- An **App Registration** in Microsoft Entra ID (see below)

## Configure the App Registration

1. Go to [Azure Portal → Entra ID → App registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps)
2. Click **New registration**
3. Set:
   - **Name:** `EnterpriseSecurityIQ Dashboard`
   - **Supported account types:** Accounts in this organizational directory only
   - **Redirect URI:** `Single-page application (SPA)` → `http://localhost:8080`
4. After creation, copy the **Application (client) ID** and **Directory (tenant) ID**
5. Under **API permissions**, add:
   - `User.Read` (delegated) — should be added by default
6. Under **Authentication → Implicit grant**, ensure **Access tokens** and **ID tokens** are checked for SPA redirect

## Configure the Dashboard

Open `index.html` and update the MSAL configuration near the top of the `<script>` section:

```javascript
const MSAL_CONFIG = {
  auth: {
    clientId: "YOUR-CLIENT-ID-HERE",    // From step 4 above
    authority: "https://login.microsoftonline.com/YOUR-TENANT-ID-HERE",
    redirectUri: window.location.origin,
  }
};
```

Also update the agent endpoint URL:

```javascript
const AGENT_URL = "https://your-agent.azurecontainerapps.io";
```

## Run Locally

Option 1 — Python:
```bash
cd webapp
python -m http.server 8080
# Open http://localhost:8080
```

Option 2 — Node.js:
```bash
npx serve webapp -l 8080
```

Option 3 — VS Code Live Server:
Right-click `index.html` → **Open with Live Server**

> **Note:** MSAL requires the page to be served over HTTP/HTTPS (not `file://`).

## Deploy to Azure Static Web Apps

### Via Azure CLI

```bash
# Install the SWA CLI
npm install -g @azure/static-web-apps-cli

# Build isn't needed (plain HTML/JS), just deploy
swa deploy ./webapp \
  --deployment-token <YOUR_DEPLOYMENT_TOKEN> \
  --env production
```

### Via Azure Portal

1. Go to **Azure Portal → Static Web Apps → Create**
2. Source: **Other** (manual deployment)
3. After creation, go to **Overview → Manage deployment token** and copy the token
4. Use the SWA CLI command above with the token

### Adding the Redirect URI

After deploying, add the Static Web App URL to your App Registration:
1. Go to **Entra ID → App registrations → EnterpriseSecurityIQ Dashboard → Authentication**
2. Under **Single-page application → Redirect URIs**, add: `https://<your-swa>.azurestaticapps.net`

## File Structure

```
webapp/
├── index.html          Single-page application (HTML + CSS + JS)
└── README.md           This file
```
