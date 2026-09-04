import json
from typing import Optional
from fastapi import APIRouter, Depends, Form, Header, Request, status
from fastapi.responses import RedirectResponse

from app.core.deps import CurrentUserId
from app.core.limiter import limiter
from app.schemas.auth import (
    AppleAuthRequest,
    GoogleAuthRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
    UserUpdateProfile,
)
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(request: Request, data: UserRegister):
    client_ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)
    return await AuthService.register(data, client_ip=client_ip)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("15/minute")
async def login(request: Request, data: UserLogin):
    client_ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)
    return await AuthService.authenticate(data, client_ip=client_ip)


@router.post("/oauth/google", response_model=TokenResponse)
@limiter.limit("15/minute")
async def google_auth(request: Request, data: GoogleAuthRequest):
    return await AuthService.authenticate_google(data)


@router.post("/oauth/apple", response_model=TokenResponse)
@limiter.limit("15/minute")
async def apple_auth(request: Request, data: AppleAuthRequest):
    return await AuthService.authenticate_apple(data)


@router.api_route("/oauth/apple/callback", methods=["GET", "POST"])
async def apple_callback(
    code: Optional[str] = Form(None),
    id_token: Optional[str] = Form(None),
    user: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    error: Optional[str] = Form(None),
):
    target_origin = "https://tasks.ayeapps.com"
    app_client_name = "tasks"
    if state:
        try:
            from urllib.parse import unquote
            state_decoded = unquote(state)
            state_data = json.loads(state_decoded)
            if isinstance(state_data, dict):
                if state_data.get("origin"):
                    target_origin = state_data["origin"].rstrip("/")
                if state_data.get("app"):
                    app_client_name = state_data["app"]
        except Exception:
            if state.startswith("http://") or state.startswith("https://"):
                target_origin = state.rstrip("/")

    if error:
        return RedirectResponse(
            url=f"{target_origin}/?error={error}",
            status_code=303,
        )

    if not id_token:
        return RedirectResponse(
            url=f"{target_origin}/?error=apple_auth_failed",
            status_code=303,
        )

    user_name = None
    user_email = None
    if user:
        try:
            user_data = json.loads(user)
            name_data = user_data.get("name", {})
            user_name = f"{name_data.get('firstName', '')} {name_data.get('lastName', '')}".strip() or None
            user_email = user_data.get("email")
        except Exception:
            pass

    try:
        auth_request = AppleAuthRequest(
            identity_token=id_token,
            name=user_name,
            email=user_email,
            app_client=app_client_name,
        )
        tokens = await AuthService.authenticate_apple(auth_request)
        redirect_url = f"{target_origin}/#access_token={tokens.access_token}&refresh_token={tokens.refresh_token}"
        return RedirectResponse(url=redirect_url, status_code=303)
    except Exception as e:
        return RedirectResponse(
            url=f"{target_origin}/?error=apple_auth_failed",
            status_code=303,
        )


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh(request: Request, data: RefreshTokenRequest):
    return await AuthService.refresh(data.refresh_token)


@router.delete("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    user_id: CurrentUserId,
    authorization: Optional[str] = Header(None),
    data: Optional[RefreshTokenRequest] = None,
):
    token = authorization.replace("Bearer ", "") if authorization else ""
    refresh_tok = data.refresh_token if data else None
    await AuthService.logout(token, refresh_tok)
    return None


@router.get("/me", response_model=UserResponse)
async def get_me(user_id: CurrentUserId):
    return await AuthService.get_user_by_id(user_id)


@router.put("/me", response_model=UserResponse)
async def update_me(user_id: CurrentUserId, data: UserUpdateProfile):
    return await AuthService.update_profile(user_id, data)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(
    user_id: CurrentUserId,
    authorization: Optional[str] = Header(None),
):
    token = authorization.replace("Bearer ", "") if authorization else ""
    await AuthService.delete_account(user_id, token)
    return None
