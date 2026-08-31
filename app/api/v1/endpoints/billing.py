from typing import List
from fastapi import APIRouter, Depends, status

from app.core.deps import CurrentUserId
from app.core.limiter import limiter
from app.schemas.billing import (
    CheckoutResponse,
    CreateCheckoutRequest,
    CreatePortalRequest,
    PlanInfo,
    PortalResponse,
)
from app.services.billing_service import BillingService

router = APIRouter()


@router.get("/plans", response_model=List[PlanInfo])
async def get_plans():
    return BillingService.get_plans()


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    user_id: CurrentUserId,
    data: CreateCheckoutRequest,
):
    return await BillingService.create_checkout_session(user_id, data)


@router.post("/portal", response_model=PortalResponse)
async def create_portal(
    user_id: CurrentUserId,
    data: CreatePortalRequest,
):
    return await BillingService.create_portal_session(user_id, data)
