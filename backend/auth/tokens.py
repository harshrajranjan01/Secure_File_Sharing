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
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expiration,

    }

    # sign the tocken using HS256
    token = jwt.encode(
        payload,
        secret_key,
        algorithm="HS256"
    )

    return token


def verify_access_token(token: str) -> dict | None:

    if not isinstance(token, str) or not token.strip():
        return None

    secret_key = os.getenv("JWT_SECRET_KEY")

    if not secret_key or not secret_key.strip():
        return None

    try:
        # Decode and validate the JWT
        claim = jwt.decode(token, secret_key, algorithms=["HS256"],
                           options={"require": ["sub", "iat", "exp"],
                                    },
                           )
        # validate the subject claim
        user_id = claim.get("sub")

        if not isinstance(user_id, str):
            return None

        if not user_id.isdigit():
            return None

        if int(user_id) <= 0:
            return None

        # Reject non-canonical IDs such as "001".
        if str(int(user_id))!=user_id:
            return None

        return claim

    except jwt.PyJWTError:
        # Invalid signature, expired token, malformed token,
        # or missing required claims.
        return None