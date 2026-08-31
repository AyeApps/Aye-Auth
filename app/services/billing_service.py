from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from bson import ObjectId
from fastapi import HTTPException, status
import stripe

from app.core.config import settings
from app.core.logging import logger
from app.db.mongodb import get_database
from app.models.user import AyeUser, Subscription, SubscriptionFeatures
from app.schemas.billing import (
    CheckoutResponse,
    CreateCheckoutRequest,
    CreatePortalRequest,
    PlanInfo,
    PortalResponse,
    SubscriptionStatusResponse,
)

if settings.STRIPE_SECRET_KEY:
    stripe.api_key = settings.STRIPE_SECRET_KEY


# Definition of Ecosystem Plans & Feature Matrix
PLANS_CATALOG: Dict[str, PlanInfo] = {
    "free": PlanInfo(
        id="free",
        name="Aye Free",
        description="Plan inicial para tareas básicas y descargas estándar en el ecosistema.",
        price_monthly_usd=0.0,
        price_yearly_usd=0.0,
        features={
            "tasks_max_levels": 10,
            "video_max_quality": "1080p",
            "video_unlimited_downloads": False,
            "ai_credits_monthly": 10,
        },
        highlights=[
            "Descargas en calidad 1080p",
            "Hasta 10 niveles de tareas en grafo",
            "Sincronización multidispositivo básica",
        ],
    ),
    "pro": PlanInfo(
        id="pro",
        name="Aye Pro Atelier",
        description="Poder ilimitado para creadores y profesionales en todas las apps de AyeApps.",
        price_monthly_usd=7.99,
        price_yearly_usd=79.99,
        features={
            "tasks_max_levels": 50,
            "video_max_quality": "4K",
            "video_unlimited_downloads": True,
            "ai_credits_monthly": 500,
        },
        highlights=[
            "Descargas en 4K y 8K ultrarrápidas sin límites",
            "Niveles ilimitados en AyeTasks y grafos avanzados",
            "Acceso prioritario a nuevas apps (AyeFinance, etc.)",
            "Sincronización en tiempo real sin restricciones",
        ],
    ),
    "atelier_vip": PlanInfo(
        id="atelier_vip",
        name="Aye Atelier VIP",
        description="Membresía exclusiva con soporte prioritario y acceso a releases alfa.",
        price_monthly_usd=19.99,
        price_yearly_usd=199.99,
        features={
            "tasks_max_levels": 100,
            "video_max_quality": "8K",
            "video_unlimited_downloads": True,
            "ai_credits_monthly": 2000,
        },
        highlights=[
            "Todo lo incluido en Pro",
            "Soporte directo por canal privado con el Atelier",
            "Insignia VIP en perfil y temas visuales exclusivos",
        ],
    ),
}


class BillingService:
    @staticmethod
    def get_plans() -> List[PlanInfo]:
        return list(PLANS_CATALOG.values())

    @staticmethod
    async def create_checkout_session(
        user_id: str,
        data: CreateCheckoutRequest,
    ) -> CheckoutResponse:
        if not settings.STRIPE_SECRET_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Stripe no está configurado en las variables de entorno del servidor.",
            )

        db = get_database()
        user = await db.aye_users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

        stripe.api_key = settings.STRIPE_SECRET_KEY

        # 1. Obtain or create Stripe Customer
        customer_id = user.get("subscription", {}).get("customer_id")
        if not customer_id:
            customer = stripe.Customer.create(
                email=user["email"],
                name=user.get("name", "Usuario AyeApps"),
                metadata={
                    "aye_user_id": str(user["_id"]),
                },
            )
            customer_id = customer.id
            await db.aye_users.update_one(
                {"_id": user["_id"]},
                {"$set": {"subscription.customer_id": customer_id}},
            )

        # 2. Determine Stripe Price ID based on plan and interval
        price_id = settings.STRIPE_PRICE_ID_PRO_MONTHLY
        if data.plan == "pro":
            price_id = (
                settings.STRIPE_PRICE_ID_PRO_YEARLY
                if data.interval == "yearly"
                else settings.STRIPE_PRICE_ID_PRO_MONTHLY
            )
        elif data.plan == "atelier_vip":
            price_id = settings.STRIPE_PRICE_ID_VIP

        # Fallback dynamic price data if explicit Price IDs are not set in .env
        line_items = []
        if price_id:
            line_items.append({"price": price_id, "quantity": 1})
        else:
            plan_data = PLANS_CATALOG.get(data.plan, PLANS_CATALOG["pro"])
            unit_amount = int(
                (plan_data.price_yearly_usd if data.interval == "yearly" else plan_data.price_monthly_usd) * 100
            )
            line_items.append({
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": plan_data.name,
                        "description": plan_data.description,
                    },
                    "unit_amount": unit_amount,
                    "recurring": {
                        "interval": "year" if data.interval == "yearly" else "month",
                    },
                },
                "quantity": 1,
            })

        # 3. Create Stripe Checkout Session
        try:
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=["card"],
                mode="subscription",
                line_items=line_items,
                success_url=data.success_url + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=data.cancel_url,
                metadata={
                    "aye_user_id": str(user["_id"]),
                    "plan": data.plan,
                    "interval": data.interval,
                },
            )
            return CheckoutResponse(
                checkout_url=session.url,
                session_id=session.id,
                provider="stripe",
            )
        except Exception as e:
            logger.error(f"Error creando Checkout Session de Stripe: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error iniciando proceso de pago con Stripe: {str(e)}",
            )

    @staticmethod
    async def create_portal_session(
        user_id: str,
        data: CreatePortalRequest,
    ) -> PortalResponse:
        if not settings.STRIPE_SECRET_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Stripe no está configurado en las variables de entorno del servidor.",
            )

        db = get_database()
        user = await db.aye_users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

        customer_id = user.get("subscription", {}).get("customer_id")
        if not customer_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El usuario aún no cuenta con un historial de suscripción en Stripe.",
            )

        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=data.return_url,
            )
            return PortalResponse(portal_url=session.url)
        except Exception as e:
            logger.error(f"Error creando Portal Session de Stripe: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error abriendo portal de suscripción: {str(e)}",
            )

    @staticmethod
    async def handle_stripe_webhook(payload: bytes, sig_header: str):
        if not settings.STRIPE_WEBHOOK_SECRET:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="STRIPE_WEBHOOK_SECRET no configurado en el servidor.",
            )

        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Payload inválido")
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Firma de webhook inválida")

        event_type = event["type"]
        data_object = event["data"]["object"]
        db = get_database()

        logger.info(f"Stripe Webhook recibido: {event_type}")

        # 1. Checkout Session Completed
        if event_type == "checkout.session.completed":
            user_id = data_object.get("metadata", {}).get("aye_user_id")
            plan_name = data_object.get("metadata", {}).get("plan", "pro")
            customer_id = data_object.get("customer")
            subscription_id = data_object.get("subscription")

            if user_id:
                plan_features = PLANS_CATALOG.get(plan_name, PLANS_CATALOG["pro"]).features
                update_set = {
                    "subscription.plan": plan_name,
                    "subscription.status": "active",
                    "subscription.provider": "stripe",
                    "subscription.customer_id": customer_id,
                    "subscription.subscription_id": subscription_id,
                    "subscription.cancel_at_period_end": False,
                    "subscription.features": plan_features,
                    "updated_at": datetime.now(timezone.utc),
                }
                await db.aye_users.update_one({"_id": ObjectId(user_id)}, {"$set": update_set})
                logger.info(f"Usuario {user_id} actualizado exitosamente a plan {plan_name}.")

        # 2. Subscription Updated (Upgrade, Downgrade, Renew)
        elif event_type in ["customer.subscription.updated", "customer.subscription.created"]:
            subscription_id = data_object.get("id")
            customer_id = data_object.get("customer")
            status_val = data_object.get("status")  # active, past_due, trialing
            cancel_at_period_end = data_object.get("cancel_at_period_end", False)
            current_period_end = datetime.fromtimestamp(
                data_object.get("current_period_end", 0), tz=timezone.utc
            )

            user = await db.aye_users.find_one({"subscription.customer_id": customer_id})
            if user:
                update_set = {
                    "subscription.status": status_val,
                    "subscription.renews_at": current_period_end,
                    "subscription.cancel_at_period_end": cancel_at_period_end,
                    "subscription.subscription_id": subscription_id,
                    "updated_at": datetime.now(timezone.utc),
                }
                await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_set})
                logger.info(f"Suscripción actualizada para usuario {user['_id']}: {status_val}")

        # 3. Subscription Deleted / Canceled (Revert to Free)
        elif event_type == "customer.subscription.deleted":
            customer_id = data_object.get("customer")
            user = await db.aye_users.find_one({"subscription.customer_id": customer_id})
            if user:
                free_features = PLANS_CATALOG["free"].features
                update_set = {
                    "subscription.plan": "free",
                    "subscription.status": "canceled",
                    "subscription.subscription_id": None,
                    "subscription.cancel_at_period_end": False,
                    "subscription.features": free_features,
                    "updated_at": datetime.now(timezone.utc),
                }
                await db.aye_users.update_one({"_id": user["_id"]}, {"$set": update_set})
                logger.info(f"Usuario {user['_id']} degradado a plan Free por cancelación.")

        return {"status": "success", "received": event_type}
