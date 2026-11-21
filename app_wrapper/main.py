"""
main.py
FastAPI Web & API Wrapper for the B2B Dynamic Pricing & Commission Engine.
Delegates business logic and verification to the compiled native core_engine.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# Ensure repo/release root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Import from core_engine (compiled binary in release)
try:
    from core_engine import license_guard, pricing_engine
except ImportError as e:
    # If run from within app_wrapper/ directly
    parent_dir = Path(__file__).resolve().parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))
    try:
        from core_engine import license_guard, pricing_engine
    except ImportError:
        raise RuntimeError(f"Failed to import core_engine: {e}. Ensure core_engine is built and in Python path.")


app = FastAPI(
    title="B2B Dynamic Pricing & Commission Engine",
    description="Hybrid Protected Architecture: FastAPI Wrapper + Compiled Cython Engine",
    version="1.0.0",
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SAMPLE_ORDERS_PATH = Path(__file__).resolve().parent / "sample_orders.json"
LICENSE_FILE_PATH = BASE_DIR / "license.key"


class OrderItem(BaseModel):
    order_id: Optional[str] = None
    product: Optional[str] = "Standard Item"
    quantity: int = Field(ge=1, default=1)
    unit_price: float = Field(ge=0.0, default=0.0)
    unit_cost: Optional[float] = None
    region: Optional[str] = "OTHER"
    sales_rep: Optional[str] = "House Account"
    custom_commission_rate: Optional[float] = None


class BatchCalculationRequest(BaseModel):
    orders: list[OrderItem]


@app.get("/", response_class=HTMLResponse)
async def index_view(request: Request):
    """Renders dashboard UI with current license status and sample order loader."""
    license_status_info = {}
    try:
        license_status_info = license_guard.verify_license(str(LICENSE_FILE_PATH))
    except Exception as e:
        license_status_info = {
            "status": "INVALID",
            "error": str(e),
        }

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "license": license_status_info,
        },
    )


@app.get("/api/license-status")
async def get_license_status():
    """Inspects and returns live Ed25519 license status."""
    try:
        info = license_guard.verify_license(str(LICENSE_FILE_PATH))
        return JSONResponse(status_code=status.HTTP_200_OK, content=info)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "INVALID",
                "error": str(e),
            },
        )


@app.post("/api/upload-license")
async def upload_license(file: UploadFile = File(...)):
    """
    Allows user to upload a new license.key file via UI or API.
    Saves file to working directory and verifies immediately without server reboot.
    """
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded license file is empty.")

        # Write to license.key in BASE_DIR
        with open(LICENSE_FILE_PATH, "wb") as f:
            f.write(content)

        # Immediate verification
        verification = license_guard.verify_license(str(LICENSE_FILE_PATH))
        return {
            "status": "SUCCESS",
            "message": "License uploaded and verified successfully.",
            "client_name": verification.get("client_name"),
            "tier": verification.get("tier"),
            "expires_at_iso": verification.get("expires_at_iso"),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"License verification failed: {e}",
        )


@app.get("/api/sample-orders")
async def get_sample_orders():
    """Returns sample B2B orders for 1-click loading."""
    if not SAMPLE_ORDERS_PATH.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="sample_orders.json not found.")

    with open(SAMPLE_ORDERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@app.post("/api/calculate")
async def calculate_pricing(payload: BatchCalculationRequest):
    """
    Executes pricing engine calculation over batch of orders.
    Enforces valid license in compiled native binary before processing.
    """
    # Convert Pydantic order items to list of dicts
    orders_data = [
        item.model_dump(exclude_none=True) if hasattr(item, "model_dump") else item.dict(exclude_none=True)
        for item in payload.orders
    ]

    if not orders_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Orders list cannot be empty.")

    try:
        result = pricing_engine.calculate_batch(orders_data, license_path=str(LICENSE_FILE_PATH))
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)
    except RuntimeError as e:
        # Cryptographic license verification or runtime error raised from compiled core
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Engine License Enforcement Block: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Calculation engine error: {str(e)}",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

