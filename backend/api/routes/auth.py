from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field


from backend.auth.passwords import (
    hash_password,
    verify_password,
)

from backend.database.user_repository import (
    create_user,
    get_user_by_username,
    DuplicateUsernameError,
)

from backend.auth.tokens import create_access_token


router = APIRouter()


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class RegisterResponse(BaseModel):
    id: int
    username: str

class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)

class LoginResponse(BaseModel):
    access_token: str
    token_type: str


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

@router.post("/auth/login",response_model=LoginResponse)
def login_user(user:LoginRequest):

    db_user=get_user_by_username(user.username)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not verify_password(user.password,db_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # 4. Create a JWT for the authenticated user.
    access_token=create_access_token(db_user["id"])

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
    )