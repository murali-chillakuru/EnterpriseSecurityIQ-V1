"""
EnterpriseSecurityIQ — Application Entry Point

Runs the FastAPI server via uvicorn on port 8088.
The API provides:
  - Web dashboard (SPA) at /
  - Agent chat with function-calling at /chat
  - Assessment endpoints at /assessments
  - Health check at /health

On startup the server also registers an assistant in the
Foundry project so it appears in the ai.azure.com portal.
"""

import uvicorn
from dotenv import load_dotenv

load_dotenv(override=False)  # Foundry runtime vars take precedence

if __name__ == "__main__":
    uvicorn.run("app.api:app", host="0.0.0.0", port=8088, log_level="info")
