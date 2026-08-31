from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.core.config import settings
from app.core.logging import logger

client: AsyncIOMotorClient = None
db: AsyncIOMotorDatabase = None


async def init_db():
    global client, db
    try:
        logger.info(f"Connecting to MongoDB at {settings.MONGODB_URL.split('@')[-1]}...")
        client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            maxPoolSize=20,
            minPoolSize=2,
            serverSelectionTimeoutMS=5000,
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
