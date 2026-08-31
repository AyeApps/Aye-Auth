from fastapi import APIRouter
from app.api.v1.endpoints import auth, billing, webhooks

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & Identity"])
api_router.include_router(billing.router, prefix="/billing", tags=["Billing & Subscriptions"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Payment Webhooks"])
