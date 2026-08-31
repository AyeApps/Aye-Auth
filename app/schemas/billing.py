from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PlanFeatureItem(BaseModel):
    name: str
    description: str
    included: bool


class PlanInfo(BaseModel):
    id: str  # 'free' | 'pro' | 'atelier_vip'
    name: str
    description: str
    price_monthly_usd: float
    price_yearly_usd: float
    features: Dict[str, Any]
    highlights: List[str]


class CreateCheckoutRequest(BaseModel):
    plan: str = "pro"  # 'pro' | 'atelier_vip'
    interval: str = "monthly"  # 'monthly' | 'yearly'
    provider: str = "stripe"  # 'stripe' | 'paypal'
    success_url: Optional[str] = "https://accounts.ayeapps.com/billing/success"
    cancel_url: Optional[str] = "https://accounts.ayeapps.com/billing/cancel"


class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: Optional[str] = None
    provider: str


class CreatePortalRequest(BaseModel):
    return_url: Optional[str] = "https://accounts.ayeapps.com/billing"


class PortalResponse(BaseModel):
    portal_url: str


class SubscriptionStatusResponse(BaseModel):
    plan: str
    status: str
    provider: Optional[str] = None
    renews_at: Optional[datetime] = None
    cancel_at_period_end: bool = False
    features: Dict[str, Any]
