
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from unittest.mock import patch

import pytest

from backend.auth.dependencies import get_current_user_id


def test_valid_token_returns_user_id():
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="valid-token",
    )

    with patch(
        "backend.auth.dependencies.verify_access_token",
        return_value={"sub": "42"},
    ):
        assert get_current_user_id(credentials) == 42


def test_missing_credentials_returns_401():
    with pytest.raises(HTTPException) as exc:
        get_current_user_id(None)

    assert exc.value.status_code == 401


def test_invalid_token_returns_401():
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="invalid-token",
    )

    with patch(
        "backend.auth.dependencies.verify_access_token",
        return_value=None,
    ):
        with pytest.raises(HTTPException) as exc:
            get_current_user_id(credentials)

    assert exc.value.status_code == 401


@pytest.mark.parametrize("sub", [None, "", "abc", "0", "-5", 42])
def test_invalid_user_id_claim_returns_401(sub):
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="valid-token",
    )

    with patch(
        "backend.auth.dependencies.verify_access_token",
        return_value={"sub": sub},
    ):
        with pytest.raises(HTTPException) as exc:
            get_current_user_id(credentials)

    assert exc.value.status_code == 401
