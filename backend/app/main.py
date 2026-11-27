import os
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import httpx

app = FastAPI(
    title="CloudSentinel AI Control Plane API",
    version="1.0.0",
    description="Modular FastAPI backend for multi-cloud insider threat detection, UBA, and cost-aware adaptive policy optimization.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml_service:8001")


class NormalizedEventIn(BaseModel):
    event_id: str
    provider: str
    event_time: str
    cloud_user_id: str
    action: str
    resource: str
    source_ip: str
    status: str
    raw_event: Dict[str, Any] = Field(default_factory=dict)


class DetectionRequest(BaseModel):
    events: List[NormalizedEventIn]
    model_type: str = "isolation_forest"


def require_role(allowed_roles: List[str]):
    def verifier(x_cloudsentinel_role: Optional[str] = Header(default="Viewer")):
        if x_cloudsentinel_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{x_cloudsentinel_role}' not authorized. Required: {allowed_roles}",
            )
        return x_cloudsentinel_role
    return verifier


@app.get("/health")
async def health():
    return {"status": "ok", "service": "cloudsentinel-fastapi-backend", "ml_service_url": ML_SERVICE_URL}


@app.post("/api/v1/detection/predict")
async def proxy_ml_detection(
    payload: DetectionRequest,
    _role: str = Depends(require_role(["Admin", "Security Analyst"])),
):
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(f"{ML_SERVICE_URL}/predict", json=payload.model_dump())
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Python ML microservice unavailable at {ML_SERVICE_URL}: {str(exc)}",
            )


@app.post("/api/v1/policies/{policy_id}/approve")
async def approve_policy(
    policy_id: str,
    _role: str = Depends(require_role(["Admin"])),
):
    return {
        "policy_id": policy_id,
        "approval_status": "Approved",
        "enforced_by": "Admin Human-in-the-Loop Gate",
    }
