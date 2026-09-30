"""
Database Initialization Script
Creates tables, inserts default roles, and creates the admin user.

Usage:
    python -m scripts.init_db

Or from Docker:
    docker exec cyberary-backend python -m scripts.init_db
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.config.settings import settings
from app.database.postgres import engine, Base, async_session_factory
from app.models.user import User, Role, UserRole, DEFAULT_ROLES
from app.models.audit_log import AuditLog
from app.security.authentication import hash_password

from sqlalchemy import select


async def init_database():
    """Initialize database with tables, roles, and admin user."""
    print("=" * 60)
    print("  🛡️  CYBERARY-AI — Database Initialization")
    print("=" * 60)

    # Create all tables
    print("\n📦 Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("   ✅ Tables created successfully.")

    # Create default roles
    print("\n👥 Creating default roles...")
    async with async_session_factory() as session:
        for role_data in DEFAULT_ROLES:
            result = await session.execute(
                select(Role).where(Role.name == role_data["name"])
            )
            existing = result.scalar_one_or_none()

            if existing is None:
                role = Role(
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                )
                session.add(role)
                print(f"   ✅ Created role: {role_data['name']}")
            else:
                print(f"   ⏭️  Role already exists: {role_data['name']}")

        await session.commit()

    # Create admin user
    print("\n🔐 Creating admin user...")
    async with async_session_factory() as session:
        result = await session.execute(
            select(User).where(User.username == settings.DEFAULT_ADMIN_USERNAME)
        )
        admin = result.scalar_one_or_none()

        if admin is None:
            admin = User(
                username=settings.DEFAULT_ADMIN_USERNAME,
                email=settings.DEFAULT_ADMIN_EMAIL,
                password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
                is_active=True,
            )
            session.add(admin)
            await session.flush()

            # Assign ADMIN role
            result = await session.execute(
                select(Role).where(Role.name == "ADMIN")
            )
            admin_role = result.scalar_one_or_none()
            if admin_role:
                user_role = UserRole(
                    user_id=admin.id,
                    role_id=admin_role.id,
                )
                session.add(user_role)

            await session.commit()
            print(f"   ✅ Admin user created: {settings.DEFAULT_ADMIN_USERNAME}")
            print(f"   📧 Email: {settings.DEFAULT_ADMIN_EMAIL}")
            print(f"   🔑 Password: {settings.DEFAULT_ADMIN_PASSWORD}")
            print("   ⚠️  CHANGE THE DEFAULT PASSWORD IN PRODUCTION!")
        else:
            print(f"   ⏭️  Admin user already exists: {settings.DEFAULT_ADMIN_USERNAME}")

    print("\n" + "=" * 60)
    print("  ✅ Database initialization complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(init_database())
