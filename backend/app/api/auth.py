"""
Authentication API Endpoints
Login, registration, and user profile endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.postgres import get_db
from app.models.user import User, Role, UserRole
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserBrief
from app.schemas.common import APIResponse
from app.schemas.user import UserResponse
from app.security.authentication import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)
from app.security.audit_logger import log_action
from app.config.settings import settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=APIResponse)
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account."""
    # Check if username exists
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "CONFLICT", "message": "Username already exists."},
        )

    # Check if email exists
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "CONFLICT", "message": "Email already registered."},
        )

    # Create user
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    await db.flush()

    # Assign default VIEWER role
    result = await db.execute(select(Role).where(Role.name == "VIEWER"))
    viewer_role = result.scalar_one_or_none()
    if viewer_role:
        db.add(UserRole(user_id=str(user.id), role_id=str(viewer_role.id)))
        await db.flush()

    # Audit log
    await log_action(
        db=db,
        action="USER_REGISTER",
        user_id=str(user.id),
        target=body.username,
        target_type="user",
        result="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )

    return APIResponse.ok({"message": "User registered successfully.", "user_id": str(user.id)})


@router.post("/login", response_model=APIResponse)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate and receive a JWT token."""
    # Find user
    result = await db.execute(
        select(User)
        .options(selectinload(User.roles))
        .where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        # Audit failed login
        await log_action(
            db=db,
            action="LOGIN_FAILED",
            target=body.username,
            target_type="user",
            result="FAILURE",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Invalid username or password."},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "FORBIDDEN", "message": "Account is disabled."},
        )

    # Generate token
    roles = [role.name for role in user.roles]
    token = create_access_token(
        user_id=str(user.id),
        username=user.username,
        roles=roles,
    )

    # Audit successful login
    await log_action(
        db=db,
        action="LOGIN_SUCCESS",
        user_id=str(user.id),
        target=user.username,
        target_type="user",
        result="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )

    return APIResponse.ok(
        TokenResponse(
            access_token=token,
            expires_in=settings.JWT_EXPIRY_HOURS * 3600,
            user=UserBrief(
                id=str(user.id),
                username=user.username,
                email=user.email,
                roles=roles,
            ),
        ).model_dump()
    )


@router.get("/me", response_model=APIResponse)
async def get_profile(
    current_user: User = Depends(get_current_user),
):
    """Get the current authenticated user's profile."""
    roles = [role.name for role in current_user.roles]

    return APIResponse.ok(
        UserResponse(
            id=str(current_user.id),
            username=current_user.username,
            email=current_user.email,
            is_active=current_user.is_active,
            roles=roles,
            created_at=current_user.created_at,
            updated_at=current_user.updated_at,
        ).model_dump()
    )
