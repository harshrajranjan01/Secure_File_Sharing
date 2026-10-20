
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.auth.tokens import verify_access_token


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user_id(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> int:
    """Validate the bearer token and return the authenticated user's ID."""

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Reject missing credentials.
    if credentials is None:
        raise unauthorized

    # 2. Verify the JWT.
    claims = verify_access_token(credentials.credentials)

    if not claims:
        raise unauthorized

    # 3. Extract the user ID from the sub claim.
    user_id = claims.get("sub")

    # 4. Validate and convert the user ID.
    if not isinstance(user_id, str) or not user_id.isdecimal():
        raise unauthorized

    user_id = int(user_id)

    if user_id <= 0:
        raise unauthorized

    # 5. Return the authenticated user's ID.
    return user_id
