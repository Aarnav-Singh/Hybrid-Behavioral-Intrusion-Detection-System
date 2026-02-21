import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

log = logging.getLogger("api")

app = FastAPI(
    title="HB-IDS v2 API",
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

# TODO: Include routers
# from backend.api.routes import infer, train, graph, alerts, redteam, experiments
# app.include_router(infer.router, prefix="/api/v1")
# ...
