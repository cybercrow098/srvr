#!/usr/bin/env python3
from datetime import datetime, timedelta
from typing import Dict

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt, JWTError

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# =========================================================
# CONFIG
# =========================================================

SECRET_KEY = "super-secret-key-change-this"
ALGORITHM = "HS256"

LICENSE_START_DATE = datetime(2025, 12, 27)
LICENSE_VALID_DAYS = 2

LICENSE_DB: Dict[str, str] = {
    "DMLIB-7X9Q2-AF8KD-M3P7L": "Custom-Dev",
    "DMLIB-QA8F7-M39KD-XP2L7": "ShadowOps",
    "DMLIB-M3P7L-9QX2A-AF8KD": "CipherUnit",
    "DMLIB-8KD7F-2X9QA-M3P7L": "DaemonCore",
}

# =========================================================
# APP + RATE LIMITER
# =========================================================

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="DaemonLib License Server")

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests, slow down."},
    )

# =========================================================
# REQUEST MODELS (IMPORTANT FIX)
# =========================================================

class LicenseRequest(BaseModel):
    license_key: str

# =========================================================
# HELPERS
# =========================================================

def license_status(key: str):
    if key not in LICENSE_DB:
        raise HTTPException(status_code=401, detail="Invalid license key")

    expiry = LICENSE_START_DATE + timedelta(days=LICENSE_VALID_DAYS)
    now = datetime.utcnow()

    if now > expiry:
        raise HTTPException(status_code=403, detail="License expired")

    return {
        "user": LICENSE_DB[key],
        "expires_on": expiry.date().isoformat(),
        "days_left": (expiry - now).days,
    }

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=12)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# =========================================================
# ROUTES
# =========================================================

@app.get("/")
def root():
    return {"status": "daemonlib server online"}

@app.post("/auth")
@limiter.limit("5/minute")
def authenticate(request: Request, body: LicenseRequest):
    """
    License authentication endpoint (JSON BODY)
    """
    status = license_status(body.license_key)

    token = create_token({
        "license": body.license_key,
        "user": status["user"],
    })

    return {
        "access": "granted",
        "user": status["user"],
        "expires_on": status["expires_on"],
        "days_left": status["days_left"],
        "token": token,
    }

@app.get("/verify")
@limiter.limit("10/minute")
def verify_token(request: Request, token: str):
    """
    Token verification endpoint
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "valid": True,
            "user": payload["user"],
            "license": payload["license"],
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# =========================================================
# RUN (DEV MODE / RAILWAY COMPATIBLE)
# =========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "Blackists:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
