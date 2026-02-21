import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

import os
load_dotenv() # Load the ABUSEIPDB_API_KEY from .env

log = logging.getLogger("api")

app = FastAPI(
    title="Cyber Sentinel API",
    description="Hybrid Behavioral Intrusion Detection System v2",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

from backend.api.routes import alerts, infer
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(infer.router, prefix="/api/v1")
