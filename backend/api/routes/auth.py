from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.auth.passwords import (
    hash_password,
)

from backend.database.user_repository import (
    create_user,
    DuplicateUsernameError,
)


router = APIRouter()


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    id: int
    username: str


@router.post(
    "/auth/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(user: RegisterRequest):
    password_hash = hash_password(user.password)

    try:
        user_id = create_user(
            username=user.username,
            password_hash=password_hash,
        )
        
    except DuplicateUsernameError:
        raise HTTPException(
            status_code=409,
            detail="Username already exists.",
        )

    if user_id is None:
        raise HTTPException(
            status_code=500,
            detail="Unable to register user.",
        )

    return RegisterResponse(
        id=user_id,
        username=user.username,
    )
