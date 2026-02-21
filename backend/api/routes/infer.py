from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from backend.core.models import registry

router = APIRouter()

class ModelListResponse(BaseModel):
    id: str
    name: str
    description: str
    type: str

class ActiveModelRequest(BaseModel):
    model_id: str

@router.get("/models", response_model=List[ModelListResponse])
async def get_models():
    """List all available ML models."""
    return registry.get_available_models()

@router.get("/models/active")
async def get_active_model():
    """Get the currently active ML model."""
    model = registry.get_active_model()
    return {"id": model.id, "name": model.name}

@router.post("/models/active")
async def set_active_model(req: ActiveModelRequest):
    """Switch the active detection model."""
    success = registry.set_active_model(req.model_id)
    if not success:
        raise HTTPException(status_code=400, detail=f"Model '{req.model_id}' not found")
    return {"status": "success", "active_model": req.model_id}
