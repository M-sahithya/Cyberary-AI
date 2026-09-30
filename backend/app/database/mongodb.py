"""
MongoDB Database Configuration
Motor async client for flexible security logs.
Falls back to in-memory storage when MongoDB is unavailable.
"""

import logging
from typing import Optional

logger = logging.getLogger("cyberary.mongodb")

# MongoDB client (initialized on startup)
_client = None
_db = None
_fallback_mode = False

# In-memory fallback collections for local dev without MongoDB
_memory_collections: dict = {}


class MemoryCollection:
    """Simple in-memory collection that mimics basic MongoDB operations for local dev."""

    def __init__(self, name: str):
        self.name = name
        self._docs = []

    async def insert_one(self, doc):
        self._docs.append(doc)
        return type("Result", (), {"inserted_id": len(self._docs) - 1})()

    async def find(self, query=None):
        return self._docs

    async def find_one(self, query=None):
        return self._docs[0] if self._docs else None

    async def count_documents(self, query=None):
        return len(self._docs)


async def init_mongodb():
    """Initialize MongoDB connection on startup. Falls back to in-memory if unavailable."""
    global _client, _db, _fallback_mode

    try:
        from app.config.settings import settings
        from motor.motor_asyncio import AsyncIOMotorClient

        _client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=3000)
        # Test connection
        await _client.admin.command("ping")
        _db = _client[settings.MONGO_DB]

        # Create collections
        collections = await _db.list_collection_names()
        for coll_name in [
            "honeypot_sessions", "terminal_events", "threat_events",
            "llm_analysis", "attack_timelines", "raw_security_logs",
        ]:
            if coll_name not in collections:
                await _db.create_collection(coll_name)

        logger.info("✅ MongoDB connected successfully.")

    except Exception as e:
        logger.warning(f"⚠️ MongoDB unavailable ({e}). Using in-memory fallback for logs.")
        _fallback_mode = True
        _client = None
        _db = None


async def close_mongodb():
    """Close MongoDB connection on shutdown."""
    global _client
    if _client:
        _client.close()


def get_mongodb():
    """Get the MongoDB database instance."""
    if _fallback_mode:
        return None
    return _db


def get_mongo_collection(collection_name: str):
    """Get a specific MongoDB collection. Returns in-memory fallback if MongoDB is unavailable."""
    if _fallback_mode or _db is None:
        if collection_name not in _memory_collections:
            _memory_collections[collection_name] = MemoryCollection(collection_name)
        return _memory_collections[collection_name]
    return _db[collection_name]
