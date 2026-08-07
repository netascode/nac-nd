"""Shared fixtures: a routing `httpx.MockTransport` standing in for a cluster."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import replace
from typing import Any

import httpx
import pytest

from nac_nd.client import NDClient
from nac_nd.config import Config
from nac_nd.log import configure_logging

Handler = Callable[[httpx.Request], httpx.Response]
Route = httpx.Response | list[httpx.Response] | Handler


def json_response(payload: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


LOGIN_RESPONSE = json_response(
    {
        "jwttoken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig",
        "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig",
        "statusCode": 200,
        "username": "admin",
    }
)


class Lab:
    """Routes requests by URL path, recording every request that arrives.

    A route may be a single response, a list consumed in order with the last
    entry repeating, or a callable.
    """

    def __init__(self, routes: dict[str, Route] | None = None) -> None:
        self.routes: dict[str, Route] = {"/api/v1/infra/login": LOGIN_RESPONSE}
        self.routes.update(routes or {})
        self.requests: list[httpx.Request] = []

    def add(self, path: str, route: Route) -> None:
        self.routes[path] = route

    def requests_to(self, path: str) -> list[httpx.Request]:
        return [request for request in self.requests if request.url.path == path]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get(request.url.path)
        if route is None:
            return json_response({"message": f"no route for {request.url.path}"}, 404)
        if isinstance(route, list):
            return route.pop(0) if len(route) > 1 else route[0]
        if callable(route):
            return route(request)
        return route


@pytest.fixture
def config() -> Config:
    return Config(
        host="nd.example.com",
        username="admin",
        password="s3cr3t",
        fabric="FABRIC-A",
        verify_ssl=False,
        poll_interval_seconds=1,
        job_timeout_minutes=1,
    )


@pytest.fixture
def make_client(config: Config) -> Iterator[Callable[..., NDClient]]:
    opened: list[httpx.Client] = []

    def factory(lab: Lab, **overrides: Any) -> NDClient:
        http = httpx.Client(transport=httpx.MockTransport(lab))
        opened.append(http)
        return NDClient(replace(config, **overrides), http=http)

    yield factory
    for http in opened:
        http.close()


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(verbose=False)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop polling loops waiting during unit tests."""
    monkeypatch.setattr("nac_nd.client.time.sleep", lambda _seconds: None)
