from typing import Any

import httpx


class AuthForgeError(Exception):
    def __init__(self, status: int, code: str, message: str, request_id: str | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.request_id = status, code, request_id


def _raise(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        error = response.json().get("error", {})
    except ValueError:
        error = {}
    raise AuthForgeError(response.status_code, error.get("code", "HTTP_ERROR"), error.get("message", "AuthForge request failed"), error.get("request_id"))


class AuthForge:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 10.0) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout)

    def application(self) -> dict[str, Any]:
        response = self._client.get("/api/v1/service/application")
        _raise(response)
        return dict(response.json())

    def close(self) -> None:
        self._client.close()


class AsyncAuthForge:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 10.0) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout)

    async def application(self) -> dict[str, Any]:
        response = await self._client.get("/api/v1/service/application")
        _raise(response)
        return dict(response.json())

    async def aclose(self) -> None:
        await self._client.aclose()

