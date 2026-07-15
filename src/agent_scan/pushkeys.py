"""Push key minting and revocation helpers for remote hook servers."""

from __future__ import annotations

import json
import logging
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from agent_scan.hook_version import HOOK_VERSION

logger = logging.getLogger(__name__)

PLATFORM_API_VERSION = "2025-08-28"


class GuardEnabledAccessDeniedError(Exception):
    """The tenant hook-status endpoint returned HTTP 403 for this principal."""


def _build_push_key_url(base_url: str, tenant_id: str) -> str:
    base = base_url.rstrip("/")
    return f"{base}/tenants/{tenant_id}/agent-scan/push-key?version={PLATFORM_API_VERSION}"


def _build_guard_enabled_url(base_url: str, tenant_id: str) -> str:
    base = base_url.rstrip("/")
    return f"{base}/tenants/{tenant_id}/agent-scan/hooks-enabled?version={HOOK_VERSION}"


def _is_localhost(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


def mint_push_key(
    base_url: str,
    tenant_id: str,
    admin_token: str,
    description: str | None = None,
) -> str:
    """Mint a new push key via a remote hook platform API.

    Returns the client_id (push key) string.
    Raises RuntimeError on failure.
    """
    url = _build_push_key_url(base_url, tenant_id)

    body = json.dumps({"description": description}).encode() if description else b""

    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if admin_token and not _is_localhost(base_url):
        req.add_header("Authorization", f"token {admin_token}")

    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except HTTPError as e:
        body_text = e.read().decode(errors="replace")
        raise RuntimeError(f"Push key minting failed: HTTP {e.code} — {body_text}") from e
    except (TimeoutError, URLError) as e:
        raise RuntimeError(f"Push key minting failed: {e}") from e

    client_id = data.get("client_id")
    if not client_id:
        raise RuntimeError(f"Unexpected push key response: {data}")
    return client_id


def fetch_guard_enabled(base_url: str, tenant_id: str, admin_token: str) -> bool:
    """Query whether agent hooks are enabled for the tenant.

    Uses the same base URL as push-key and hook-event APIs.

    Returns True if ``enabled`` is true in the JSON body; False if explicitly disabled.
    Raises RuntimeError on HTTP errors or unexpected response shape.
    """
    url = _build_guard_enabled_url(base_url, tenant_id)
    req = Request(url, method="GET")
    if admin_token and not _is_localhost(base_url):
        req.add_header("Authorization", f"token {admin_token}")
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except HTTPError as e:
        body_text = e.read().decode(errors="replace")
        if e.code == 403:
            raise GuardEnabledAccessDeniedError(body_text) from e
        # Do not include body_text in the raised message (may contain internal or sensitive details).
        logger.debug("guard_enabled HTTP %s: %s", e.code, body_text[:2000])
        raise RuntimeError(f"Guard enabled check failed: HTTP {e.code}, url: {url}") from e
    except (TimeoutError, URLError) as e:
        logger.debug("guard_enabled network error", exc_info=True)
        raise RuntimeError("Guard enabled check failed: network error") from e

    if not isinstance(data, dict) or "enabled" not in data:
        logger.debug("guard_enabled unexpected JSON shape: %r", data)
        raise RuntimeError("Unexpected guard-enabled response from server")
    return bool(data["enabled"])


def revoke_push_key(
    base_url: str,
    tenant_id: str,
    admin_token: str,
    client_id: str,
) -> None:
    """Revoke a push key via a remote hook platform API.

    Raises RuntimeError on failure.
    """
    url = _build_push_key_url(base_url, tenant_id)

    req = Request(url, method="DELETE")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-client-id", client_id)
    if admin_token and not _is_localhost(base_url):
        req.add_header("Authorization", f"token {admin_token}")

    try:
        with urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"Push key revocation failed: HTTP {resp.status}")
    except HTTPError as e:
        body_text = e.read().decode(errors="replace")
        raise RuntimeError(f"Push key revocation failed: HTTP {e.code} — {body_text}") from e
    except (TimeoutError, URLError) as e:
        raise RuntimeError(f"Push key revocation failed: {e}") from e
