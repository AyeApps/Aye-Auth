from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: str = Field(min_length=1, max_length=100)
    preferred_language: Optional[str] = "es"
    preferred_theme: Optional[str] = "dark"
    timezone: Optional[str] = "America/Mexico_City"
    app_client: Optional[str] = "tasks"


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    app_client: Optional[str] = "tasks"


class GoogleAuthRequest(BaseModel):
    id_token: str
    app_client: Optional[str] = "tasks"


class AppleAuthRequest(BaseModel):
    identity_token: str
    name: Optional[str] = None
    email: Optional[str] = None
    app_client: Optional[str] = "tasks"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserUpdateProfile(BaseModel):
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    preferred_language: Optional[str] = None
    preferred_theme: Optional[str] = None
    timezone: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8)


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    avatar_url: Optional[str] = None
    preferred_language: str
    preferred_theme: str
    timezone: str
    apps_access: Dict[str, bool]
    subscription: Dict[str, Any]
    created_at: datetime
    last_login_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
