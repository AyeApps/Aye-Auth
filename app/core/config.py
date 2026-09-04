import json
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "AyeAuth"
    APP_ENV: str = "development"
    PORT: int = 8000
    MONGODB_URL: str = "mongodb://localhost:27017/aye_identity"
    DATABASE_NAME: str = "aye_identity"
    MONGODB_CERT_B64: str = ""
    MONGODB_CERT_PATH: str = ""

    # Security & Tokens
    JWT_SECRET_KEY: str = "super_secure_secret_key_minimum_32_characters_for_ayeapps_atelier"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # CORS
    CORS_ORIGINS: Union[List[str], str] = [
        "https://tasks.ayeapps.com",
        "https://video.ayeapps.com",
        "https://finance.ayeapps.com",
        "https://ayeapps.com",
        "https://accounts.ayeapps.com",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
        "http://localhost:8081",
        "http://localhost:8083",
        "ayevideo://app",
        "ayetasks://app",
        "ayefinance://app",
    ]

    # Billing & Subscriptions (Stripe / PayPal)
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_ID_PRO_MONTHLY: str = ""
    STRIPE_PRICE_ID_PRO_YEARLY: str = ""
    STRIPE_PRICE_ID_VIP: str = ""
    PAYPAL_CLIENT_ID: str = ""
    PAYPAL_CLIENT_SECRET: str = ""
    PAYPAL_WEBHOOK_ID: str = ""

    # OAuth Providers
    GOOGLE_CLIENT_IDS: List[str] = [
        "627799707976-gt9uudejrtd5d4b7pubkso0ev35j2rhr.apps.googleusercontent.com",
        "627799707976-dmm76mhsvc1b7d7jcrf2hpfjbtnpb6te.apps.googleusercontent.com",
        "627799707976-ek7dcu7lgfuj06us18cu5gnfuf6n3qqt.apps.googleusercontent.com",
    ]
    APPLE_CLIENT_IDS: List[str] = [
        "com.ayeapps.ayetasks",
        "com.ayeapps.ayetasks.auth",
        "com.ayeapps.ayevideodownloader",
        "com.ayeapps.ayefinance",
        "com.ayeapps.ayefinance.auth",
        "com.ayeapps.auth",
    ]
    APPLE_BUNDLE_ID: str = "com.ayeapps.ayetasks"

    # Cloudflare Turnstile Bot Protection
    TURNSTILE_SECRET_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, str) and v.startswith("["):
            try:
                return json.loads(v)
            except Exception:
                return ["*"]
        return v


settings = Settings()
