import os

from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv

load_dotenv()


def create_access_token(user_id: int) -> str:
    """Create a signed JWT access token for a user"""

    # Validate the user ID.
    # bool is a subclass of int in Python, so reject it explicitly.

    if isinstance(user_id, bool) or not isinstance(user_id, int):
        raise TypeError("User ID must be an integer.")

    if user_id <= 0:
        raise ValueError("User ID must be a positive integer.")

    secret_key = os.getenv("JWT_SECRET_KEY")

    if not secret_key or not secret_key.strip():
        raise RuntimeError("JWT_SECRET_KEY is not configured.")

    # set the token expiration time to 15 min from now.
    now = datetime.now(timezone.utc)
    expiration = now+timedelta(minutes=15)

    # Define the information stored inside the token.
    payload={
        "sub":str(user_id),
        "iat":now,
        "exp":expiration,

    }

    #sign the tocken using HS256
    token=jwt.encode(
        payload,
        secret_key,
        algorithm="HS256"
        )

    return token