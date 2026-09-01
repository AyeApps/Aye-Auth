from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from bson import ObjectId
from fastapi import HTTPException, status
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
import httpx
from jose import jwt

from app.core.config import settings
from app.core.logging import logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.mongodb import get_database
from app.models.revoked_token import RefreshTokenDoc, RevokedToken
from app.models.user import AppsAccess, AuthProviders, AyeUser, Subscription
from app.schemas.auth import (
    AppleAuthRequest,
    GoogleAuthRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
    UserUpdateProfile,
)


def verify_google_id_token(token: str) -> dict:
    try:
        idinfo = google_id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
        )
        aud = idinfo.get("aud")
        if aud not in settings.GOOGLE_CLIENT_IDS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Audience de Google ID token no autorizada",
            )
        return idinfo
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Google ID token inválido: {str(e)}",
        )


async def verify_apple_id_token(token: str) -> dict:
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Apple token sin kid",
            )

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get("https://appleid.apple.com/auth/keys")
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="No se pudo contactar a los servidores de Apple",
                )
            apple_keys = resp.json().get("keys", [])

        key = next((k for k in apple_keys if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Clave pública de Apple no encontrada",
            )

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer="https://appleid.apple.com",
            options={"verify_at_hash": False, "verify_aud": False},
        )
        aud = payload.get("aud")
        if aud not in settings.APPLE_CLIENT_IDS and aud != settings.APPLE_BUNDLE_ID:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Audience de Apple identity token no autorizada: {aud}",
            )
        return payload
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Apple identity token inválido: {str(e)}",
        )


def _build_user_response(user_dict: dict) -> UserResponse:
    user_id = str(user_dict.get("_id", ""))
    return UserResponse(
        id=user_id,
        email=user_dict["email"],
        name=user_dict.get("name", "Usuario"),
        avatar_url=user_dict.get("avatar_url"),
        preferred_language=user_dict.get("preferred_language", "es"),
        preferred_theme=user_dict.get("preferred_theme", "dark"),
        timezone=user_dict.get("timezone", "America/Mexico_City"),
        apps_access=user_dict.get("apps_access", {}),
        subscription=user_dict.get("subscription", {}),
        created_at=user_dict.get("created_at", datetime.now(timezone.utc)),
        last_login_at=user_dict.get("last_login_at", datetime.now(timezone.utc)),
    )


def _generate_token_response(user_dict: dict) -> TokenResponse:
    user_id = str(user_dict.get("_id", ""))
    subscription_plan = user_dict.get("subscription", {}).get("plan", "free")
    
    claims = {
        "email": user_dict["email"],
        "name": user_dict.get("name", "Usuario"),
        "avatar_url": user_dict.get("avatar_url"),
        "tier": subscription_plan,
        "apps_access": user_dict.get("apps_access", {}),
    }

    access_token = create_access_token(user_id, claims=claims)
    refresh_token = create_refresh_token(user_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_build_user_response(user_dict),
    )


class AuthService:
    @staticmethod
    async def register(data: UserRegister) -> TokenResponse:
        db = get_database()
        email_clean = data.email.lower().strip()
        existing = await db.aye_users.find_one({"email": email_clean})
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El correo electrónico ya está registrado en el ecosistema AyeApps",
            )

        now = datetime.now(timezone.utc)
        apps_access = AppsAccess().model_dump()
        if data.app_client:
            apps_access[data.app_client] = True

        new_user = {
            "email": email_clean,
            "hashed_password": hash_password(data.password),
            "name": data.name.strip(),
            "avatar_url": None,
            "preferred_language": data.preferred_language or "es",
            "preferred_theme": data.preferred_theme or "dark",
            "timezone": data.timezone or "America/Mexico_City",
            "auth_providers": AuthProviders().model_dump(),
            "apps_access": apps_access,
            "subscription": Subscription().model_dump(),
            "is_active": True,
            "is_verified": False,
            "login_attempts": 0,
            "locked_until": None,
            "created_at": now,
            "updated_at": now,
            "last_login_at": now,
            "deleted_at": None,
        }

        result = await db.aye_users.insert_one(new_user)
        new_user["_id"] = result.inserted_id

        # Persist initial refresh token
        token_resp = _generate_token_response(new_user)
        await db.aye_refresh_tokens.insert_one({
            "user_id": str(result.inserted_id),
            "token": token_resp.refresh_token,
            "created_at": now,
            "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        })

        return token_resp

    @staticmethod
    async def authenticate(data: UserLogin) -> TokenResponse:
        db = get_database()
        email_clean = data.email.lower().strip()
        user = await db.aye_users.find_one({"email": email_clean})

        if not user or user.get("deleted_at") is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="ACCOUNT_NOT_FOUND",
            )

        # Check account lockout
        locked_until = user.get("locked_until")
        if locked_until and locked_until > datetime.now(timezone.utc):
            minutes_left = int((locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Cuenta temporalmente bloqueada. Reintenta en {minutes_left} minutos.",
            )

        # Check password
        hashed = user.get("hashed_password")
        if not hashed or not verify_password(data.password, hashed):
            attempts = user.get("login_attempts", 0) + 1
            update_fields = {"login_attempts": attempts}
            if attempts >= 5:
                update_fields["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=15)
                update_fields["login_attempts"] = 0
            await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_fields})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="INVALID_PASSWORD",
            )

        # Successful login: reset attempts, update app access & last login
        now = datetime.now(timezone.utc)
        update_set = {
            "login_attempts": 0,
            "locked_until": None,
            "last_login_at": now,
        }
        if data.app_client:
            update_set[f"apps_access.{data.app_client}"] = True

        await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_set})
        user = await db.aye_users.find_one({"_id": user["_id"]})

        token_resp = _generate_token_response(user)
        await db.aye_refresh_tokens.insert_one({
            "user_id": str(user["_id"]),
            "token": token_resp.refresh_token,
            "created_at": now,
            "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        })

        return token_resp

    @staticmethod
    async def authenticate_google(data: GoogleAuthRequest) -> TokenResponse:
        if data.id_token:
            idinfo = verify_google_id_token(data.id_token)
            email_clean = idinfo.get("email", "").lower().strip()
            sub = str(idinfo.get("sub"))
            name = idinfo.get("name") or "Usuario Google"
            picture = idinfo.get("picture")
        elif data.access_token:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {data.access_token}"},
                )
                if resp.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token de acceso de Google inválido",
                    )
                userinfo = resp.json()
                email_clean = userinfo.get("email", "").lower().strip()
                sub = str(userinfo.get("sub"))
                name = userinfo.get("name") or "Usuario Google"
                picture = userinfo.get("picture")
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token de Google requerido (id_token o access_token)",
            )

        if not email_clean:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La cuenta de Google no contiene un correo electrónico válido",
            )

        db = get_database()
        now = datetime.now(timezone.utc)

        user = await db.aye_users.find_one({"email": email_clean})

        if user:
            # Auto-link Google ID if not present
            update_set = {
                "auth_providers.google_id": sub,
                "is_verified": True,
                "login_attempts": 0,
                "locked_until": None,
                "last_login_at": now,
                "deleted_at": None,
                "is_active": True,
            }
            if not user.get("avatar_url") and picture:
                update_set["avatar_url"] = picture
            if data.app_client:
                update_set[f"apps_access.{data.app_client}"] = True

            await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_set})
            user = await db.aye_users.find_one({"_id": user["_id"]})
        else:
            # Auto-provision new Aye Account seamlessly
            apps_access = AppsAccess().model_dump()
            if data.app_client:
                apps_access[data.app_client] = True

            new_user = {
                "email": email_clean,
                "hashed_password": None,
                "name": name,
                "avatar_url": picture,
                "preferred_language": "es",
                "preferred_theme": "dark",
                "timezone": "America/Mexico_City",
                "auth_providers": {"google_id": sub, "apple_id": None},
                "apps_access": apps_access,
                "subscription": Subscription().model_dump(),
                "is_active": True,
                "is_verified": True,
                "login_attempts": 0,
                "locked_until": None,
                "created_at": now,
                "updated_at": now,
                "last_login_at": now,
                "deleted_at": None,
            }
            res = await db.aye_users.insert_one(new_user)
            new_user["_id"] = res.inserted_id
            user = new_user

        token_resp = _generate_token_response(user)
        await db.aye_refresh_tokens.insert_one({
            "user_id": str(user["_id"]),
            "token": token_resp.refresh_token,
            "created_at": now,
            "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        })

        return token_resp

    @staticmethod
    async def authenticate_apple(data: AppleAuthRequest) -> TokenResponse:
        payload = await verify_apple_id_token(data.identity_token)
        sub = str(payload.get("sub"))
        email_clean = (payload.get("email") or data.email or "").lower().strip()

        db = get_database()
        now = datetime.now(timezone.utc)
        user = None

        if sub:
            user = await db.aye_users.find_one({"auth_providers.apple_id": sub})
        if not user and email_clean:
            user = await db.aye_users.find_one({"email": email_clean})

        if user:
            update_set = {
                "auth_providers.apple_id": sub,
                "is_verified": True,
                "login_attempts": 0,
                "locked_until": None,
                "last_login_at": now,
                "deleted_at": None,
                "is_active": True,
            }
            if data.name and (user.get("name") in ["Usuario", "Usuario Apple"]):
                update_set["name"] = data.name.strip()
            if data.app_client:
                update_set[f"apps_access.{data.app_client}"] = True

            await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_set})
            user = await db.aye_users.find_one({"_id": user["_id"]})
        else:
            user_email = email_clean or f"{sub}@privaterelay.appleid.com"
            apps_access = AppsAccess().model_dump()
            if data.app_client:
                apps_access[data.app_client] = True

            new_user = {
                "email": user_email,
                "hashed_password": None,
                "name": data.name.strip() if data.name else "Usuario Apple",
                "avatar_url": None,
                "preferred_language": "es",
                "preferred_theme": "dark",
                "timezone": "America/Mexico_City",
                "auth_providers": {"google_id": None, "apple_id": sub},
                "apps_access": apps_access,
                "subscription": Subscription().model_dump(),
                "is_active": True,
                "is_verified": True,
                "login_attempts": 0,
                "locked_until": None,
                "created_at": now,
                "updated_at": now,
                "last_login_at": now,
                "deleted_at": None,
            }
            res = await db.aye_users.insert_one(new_user)
            new_user["_id"] = res.inserted_id
            user = new_user

        token_resp = _generate_token_response(user)
        await db.aye_refresh_tokens.insert_one({
            "user_id": str(user["_id"]),
            "token": token_resp.refresh_token,
            "created_at": now,
            "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        })

        return token_resp

    @staticmethod
    async def refresh(refresh_token: str) -> TokenResponse:
        db = get_database()
        try:
            payload = decode_token(refresh_token)
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="El token proporcionado no es un refresh token válido",
                )
            user_id = payload.get("sub")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido o expirado",
            )

        # Verify token in DB
        existing_token = await db.aye_refresh_tokens.find_one({"token": refresh_token, "user_id": user_id})
        if not existing_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token revocado o no encontrado",
            )

        user = await db.aye_users.find_one({"_id": ObjectId(user_id)})
        if not user or not user.get("is_active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario no encontrado o inactivo",
            )

        # Rotate refresh token (delete old, issue new)
        await db.aye_refresh_tokens.delete_one({"token": refresh_token})

        token_resp = _generate_token_response(user)
        now = datetime.now(timezone.utc)
        await db.aye_refresh_tokens.insert_one({
            "user_id": user_id,
            "token": token_resp.refresh_token,
            "created_at": now,
            "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        })

        return token_resp

    @staticmethod
    async def logout(access_token: str, refresh_token: Optional[str] = None):
        db = get_database()
        now = datetime.now(timezone.utc)
        if access_token:
            try:
                payload = decode_token(access_token)
                exp = datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc)
                await db.aye_revoked_tokens.insert_one({
                    "token": access_token,
                    "revoked_at": now,
                    "expires_at": exp,
                })
            except Exception:
                pass

        if refresh_token:
            await db.aye_refresh_tokens.delete_one({"token": refresh_token})

    @staticmethod
    async def get_user_by_id(user_id: str) -> UserResponse:
        db = get_database()
        user = await db.aye_users.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("deleted_at") is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )
        return _build_user_response(user)

    @staticmethod
    async def update_profile(user_id: str, data: UserUpdateProfile) -> UserResponse:
        db = get_database()
        user = await db.aye_users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        update_set = {"updated_at": datetime.now(timezone.utc)}
        if data.name is not None and data.name.strip():
            update_set["name"] = data.name.strip()
        if data.avatar_url is not None:
            update_set["avatar_url"] = data.avatar_url
        if data.preferred_language is not None:
            update_set["preferred_language"] = data.preferred_language
        if data.preferred_theme is not None:
            update_set["preferred_theme"] = data.preferred_theme
        if data.timezone is not None:
            update_set["timezone"] = data.timezone

        if data.new_password:
            if not user.get("hashed_password") or not data.current_password or not verify_password(data.current_password, user["hashed_password"]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La contraseña actual es incorrecta",
                )
            update_set["hashed_password"] = hash_password(data.new_password)

        await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_set})
        updated = await db.aye_users.find_one({"_id": user["_id"]})
        return _build_user_response(updated)

    @staticmethod
    async def delete_account(user_id: str, access_token: Optional[str] = None):
        db = get_database()
        user = await db.aye_users.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("deleted_at") is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )
        now = datetime.now(timezone.utc)
        await db.aye_users.update_one(
            {"_id": user["_id"]},
            {"$set": {"deleted_at": now, "is_active": False}}
        )
        await db.aye_refresh_tokens.delete_many({"user_id": str(user["_id"])})
        if access_token:
            try:
                payload = decode_token(access_token)
                exp = datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc)
                await db.aye_revoked_tokens.insert_one({
                    "token": access_token,
                    "revoked_at": now,
                    "expires_at": exp,
                })
            except Exception:
                pass
