from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from bson import ObjectId
from pydantic import BaseModel, Field


class PyObjectId(ObjectId):
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema

        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ObjectId),
                core_schema.chain_schema([
                    core_schema.str_schema(),
                    core_schema.no_info_plain_validator_function(cls.validate),
                ]),
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda x: str(x)),
        )

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


class AuthProviders(BaseModel):
    google_id: Optional[str] = None
    apple_id: Optional[str] = None


class AppsAccess(BaseModel):
    tasks: bool = True
    video_downloader: bool = True
    finance: bool = False


class SubscriptionFeatures(BaseModel):
    tasks_max_levels: int = 10
    video_max_quality: str = "1080p"
    video_unlimited_downloads: bool = False
    ai_credits_monthly: int = 50


class Subscription(BaseModel):
    plan: str = "free"  # free | pro | atelier_vip
    status: str = "active"  # active | canceled | past_due | trialing
    provider: Optional[str] = None  # stripe | paypal | manual
    customer_id: Optional[str] = None  # cus_... (Stripe) or PayPal Payer ID
    subscription_id: Optional[str] = None  # sub_... (Stripe) or PayPal Agreement ID
    renews_at: Optional[datetime] = None
    cancel_at_period_end: bool = False
    features: SubscriptionFeatures = Field(default_factory=SubscriptionFeatures)


class AyeUser(BaseModel):
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    email: str
    hashed_password: Optional[str] = None
    name: str = "Usuario Aye"
    avatar_url: Optional[str] = None

    # Global Preferences
    preferred_language: str = "es"  # 'es' | 'en'
    preferred_theme: str = "dark"  # 'dark' | 'light'
    timezone: str = "America/Mexico_City"

    # Identity Providers & Access
    primary_provider: str = "local"  # 'local' | 'google' | 'apple'
    auth_providers: AuthProviders = Field(default_factory=AuthProviders)
    apps_access: AppsAccess = Field(default_factory=AppsAccess)
    subscription: Subscription = Field(default_factory=Subscription)

    # Security & Status
    is_active: bool = True
    is_verified: bool = False
    login_attempts: int = 0
    locked_until: Optional[datetime] = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    deleted_at: Optional[datetime] = None

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str},
    }

    def is_locked(self) -> bool:
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return True
        return False
