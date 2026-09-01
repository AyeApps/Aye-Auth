import base64
import os
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.core.config import settings
from app.core.logging import logger

client: AsyncIOMotorClient = None
db: AsyncIOMotorDatabase = None


async def init_db():
    global client, db
    try:
        cert_path = settings.MONGODB_CERT_PATH
        if settings.MONGODB_CERT_B64 and settings.MONGODB_CERT_B64.strip():
            temp_cert = "/tmp/aye_auth_cert.pem"
            try:
                cert_bytes = base64.b64decode(settings.MONGODB_CERT_B64.strip())
                with open(temp_cert, "wb") as f:
                    f.write(cert_bytes)
                cert_path = temp_cert
                logger.info("Decoded X.509 certificate from MONGODB_CERT_B64 successfully.")
            except Exception as e:
                logger.error(f"Error decoding MONGODB_CERT_B64: {e}")

        client_kwargs = {
            "maxPoolSize": 20,
            "minPoolSize": 2,
            "serverSelectionTimeoutMS": 5000,
        }

        mongo_url = settings.MONGODB_URL
        if cert_path and os.path.exists(cert_path):
            client_kwargs["tls"] = True
            client_kwargs["tlsCertificateKeyFile"] = cert_path
            client_kwargs["authMechanism"] = "MONGODB-X509"
            client_kwargs["authSource"] = "$external"
            logger.info(f"Connecting to MongoDB with X.509 Certificate ({cert_path})...")
        else:
            logger.info(f"Connecting to MongoDB at {mongo_url.split('@')[-1]}...")

        client = AsyncIOMotorClient(
            mongo_url,
            **client_kwargs
        )
        db = client[settings.DATABASE_NAME]

        # Ensure essential unique indexes
        await db.aye_users.create_index("email", unique=True)
        await db.aye_users.create_index("auth_providers.google_id", sparse=True)
        await db.aye_users.create_index("auth_providers.apple_id", sparse=True)
        await db.aye_refresh_tokens.create_index("token", unique=True)
        await db.aye_refresh_tokens.create_index("expires_at", expireAfterSeconds=0)

        logger.info("MongoDB connection and indexes initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise e


async def close_db():
    global client
    if client:
        client.close()
        logger.info("MongoDB connection closed.")


def get_database() -> AsyncIOMotorDatabase:
    return db
