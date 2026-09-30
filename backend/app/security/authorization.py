"""
Authorization Module
Role-based access control (RBAC) dependency for FastAPI endpoints.
"""

from functools import wraps
from typing import List

from fastapi import Depends, HTTPException, status

from app.models.user import User
from app.security.authentication import get_current_user


def require_roles(allowed_roles: List[str]):
    """
    FastAPI dependency factory that checks if the current user has
    at least one of the required roles.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_roles(["ADMIN"]))])
    """
    async def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_roles = [role.name for role in current_user.roles]

        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": f"This action requires one of: {', '.join(allowed_roles)}.",
                },
            )
        return current_user

    return role_checker


def require_permission(permission: str):
    """
    FastAPI dependency factory that checks if the current user has
    a specific permission in any of their roles.

    Usage:
        @router.post("/scan", dependencies=[Depends(require_permission("run_assessment"))])
    """
    async def permission_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_permissions = set()
        for role in current_user.roles:
            if role.permissions:
                user_permissions.update(role.permissions)

        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": f"Missing required permission: {permission}.",
                },
            )
        return current_user

    return permission_checker
