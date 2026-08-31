from fastapi import APIRouter, Header, HTTPException, Request, status
from app.services.billing_service import BillingService

router = APIRouter()


@router.post("/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="Stripe-Signature"),
):
    if not stripe_signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Falta el encabezado Stripe-Signature",
        )

    payload = await request.body()
    return await BillingService.handle_stripe_webhook(payload, stripe_signature)
