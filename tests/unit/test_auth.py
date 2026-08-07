"""Authentication and session token handling."""

from __future__ import annotations

import json

import pytest

from nac_nd.client import token_from_auth_response
from nac_nd.exceptions import AuthError
from tests.conftest import Lab, json_response


def test_login_always_sends_a_domain(make_client) -> None:
    """`domain` is required; an empty or absent one returns HTTP 500."""
    lab = Lab({"/api/v1/manage/fabrics": json_response({"fabrics": []})})
    client = make_client(lab)
    client.authenticate()

    body = json.loads(lab.requests_to("/api/v1/infra/login")[0].content)
    assert body["domain"] == "DefaultAuth"
    assert body["userName"] == "admin"
    assert body["userPasswd"] == "s3cr3t"


def test_token_is_presented_as_the_auth_cookie(make_client) -> None:
    """The token travels as `Cookie: AuthCookie=<jwt>`, not as a header."""
    client = make_client(Lab())
    client.authenticate()

    assert client.client.headers["Cookie"].startswith("AuthCookie=eyJ")
    assert "authcookie" not in [name.lower() for name in client.client.headers]


def test_refresh_response_carries_jwttoken_but_no_token() -> None:
    """Login returns both spellings; refresh returns `jwttoken` only."""
    assert token_from_auth_response({"jwttoken": "abc"}) == "abc"
    assert token_from_auth_response({"jwttoken": "abc", "token": "abc"}) == "abc"

    with pytest.raises(AuthError):
        token_from_auth_response({"statusCode": 200})


def test_refresh_keeps_the_client_authenticated(make_client) -> None:
    lab = Lab({"/api/v1/infra/refresh": json_response({"jwttoken": "refreshed"})})
    client = make_client(lab)
    client.authenticate()

    client.refresh()

    assert client.token == "refreshed"
    assert client.client.headers["Cookie"] == "AuthCookie=refreshed"


def test_a_401_is_retried_once_then_raises(make_client) -> None:
    lab = Lab(
        {
            "/api/v1/manage/fabrics": json_response({"message": "denied"}, 401),
            "/api/v1/infra/refresh": json_response({"jwttoken": "refreshed"}),
        }
    )
    client = make_client(lab)

    with pytest.raises(AuthError, match="Not authorised"):
        client.list_fabrics()

    assert len(lab.requests_to("/api/v1/manage/fabrics")) == 2


def test_login_failure_reports_the_username_and_domain(make_client) -> None:
    lab = Lab()
    lab.add(
        "/api/v1/infra/login",
        json_response({"code": 401, "message": "invalid credentials"}, 401),
    )
    client = make_client(lab)

    with pytest.raises(AuthError) as caught:
        client.authenticate()

    assert caught.value.exit_code == 5
    assert "admin" in str(caught.value)
    assert "DefaultAuth" in str(caught.value)
    assert "invalid credentials" in str(caught.value)
