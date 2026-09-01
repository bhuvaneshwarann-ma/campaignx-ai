from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models import User, AuditLog
from backend.app.schemas.auth import Token, UserCreate, UserResponse
from backend.app.core.security import verify_password, get_password_hash, create_access_token
from backend.app.auth.dependencies import get_current_active_user, require_roles
from backend.app.core.config import settings
from backend.app.core.logging import logger

router = APIRouter()


@router.post("/login", response_model=Token, summary="OAuth2 compatible token login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Authenticate user with username and password, return JWT token."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    # Record login audit log
    audit = AuditLog(
        user_id=user.id,
        action="LOGIN",
        resource_type="USER",
        resource_id=user.id,
        details_json={"username": user.username, "role": user.role}
    )
    db.add(audit)
    db.commit()

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(subject=user.id, expires_delta=access_token_expires)

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Register user")
def register(
    user_in: UserCreate,
    db: Session = Depends(get_db)
):
    """Register a new user account."""
    existing_user = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )

    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role,
        is_active=user_in.is_active
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"New user registered: {user.username} (Role: {user.role})")
    return user


@router.get("/me", response_model=UserResponse, summary="Get current logged in user")
def read_current_user(current_user: User = Depends(get_current_active_user)):
    """Return profile details for current authenticated session."""
    return current_user
