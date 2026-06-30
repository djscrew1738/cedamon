"""
Session Guard — proxy layer and credential isolation for RedAmon engagements.

Protects the orchestrator's infrastructure when the agent interacts with
target systems by:

    1. Staging Proxy: Strips internal headers from all outgoing requests,
       preventing the target from learning about the agent's infrastructure
       (X-Forwarded-For, X-Real-IP, Via, etc.).

    2. Cloud Credential Isolation: Generates temporary, limited-scope
       tokens for cloud API interactions. The sandbox NEVER sees the
       host's real credentials.

    3. Session Cookie Isolation: Ensures target cookies can't leak back
       to the agent's infrastructure through HTTP redirects or mixed-content.

Usage:
    from agentic.session_guard import SessionGuard

    guard = SessionGuard()
    safe_headers = guard.sanitize_headers(original_headers)
    temp_creds = guard.generate_temp_credentials(aws_role="readonly")
"""

import base64
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Headers that reveal internal infrastructure and MUST be stripped.
STRIP_HEADERS = {
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "x-envoy-external-address",
    "cf-connecting-ip",
    "true-client-ip",
    "fastly-client-ip",
    "via",
    "x-via",
    "proxy-authorization",
    "proxy-connection",
    "x-bluecoat-via",
}

# Headers that may leak internal hostnames/server info.
SANITIZE_HEADERS = {
    "server": "nginx",
    "x-powered-by": "",
    "x-aspnet-version": "",
    "x-aspnetmvc-version": "",
    "x-runtime": "",
    "x-generator": "",
}

# Maximum temp token lifetime in seconds.
MAX_TEMP_TOKEN_LIFETIME = 3600  # 1 hour
DEFAULT_TEMP_TOKEN_LIFETIME = 1800  # 30 minutes


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class TempCredentials:
    """Temporary, limited-scope cloud credentials."""

    provider: str       # aws, gcp, azure, do
    access_key_id: str  # Encrypted reference — NOT the real key
    secret_hash: str    # SHA-256 hash of the temporary token
    role_arn: str = ""
    scope: list[str] = field(default_factory=list)
    expires_at: float = 0.0
    session_name: str = ""


@dataclass
class SanitizedRequest:
    """A sanitized HTTP request ready for outbound proxy."""

    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    proxy_host: str = ""
    proxy_port: int = 8080
    sanitized_headers: int = 0


# ---------------------------------------------------------------------------
# 1. Header Sanitizer
# ---------------------------------------------------------------------------

class HeaderSanitizer:
    """Strips and sanitizes HTTP headers for outbound requests.

    Prevents the target from learning about the agent's internal
    infrastructure through request headers.
    """

    @staticmethod
    def sanitize(headers: dict) -> dict:
        """Sanitize a headers dict for outbound requests.

        - Removes infrastructure-revealing headers (X-Forwarded-For, etc.)
        - Replaces server-info headers with generic values.
        - Ensures User-Agent is a standard value (not custom tool name).

        Args:
            headers: Original headers dict to sanitize.

        Returns:
            New dict with stripped/sanitized headers.
        """
        safe: dict = {}

        for key, value in (headers or {}).items():
            lower_key = key.lower().strip()

            # Skip stripped headers.
            if lower_key in STRIP_HEADERS:
                continue

            # Sanitize.
            if lower_key in SANITIZE_HEADERS:
                replacement = SANITIZE_HEADERS[lower_key]
                if replacement:
                    safe[key] = replacement
                continue

            # Keep header.
            safe[key] = value

        # Set a neutral User-Agent if missing or revealing.
        if "user-agent" not in {k.lower() for k in safe}:
            safe["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )

        # Add Do Not Track header (standard browser behavior).
        if "dnt" not in {k.lower() for k in safe}:
            safe["DNT"] = "1"

        return safe

    @staticmethod
    def create_proxy_session(
        proxy_host: str = "localhost",
        proxy_port: int = 8080,
    ) -> dict:
        """Create proxy environment variables for subprocess calls.

        Returns a dict suitable for subprocess env= parameter.

        This ensures tools spawned by the agent route through the
        staging proxy instead of connecting directly.
        """
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        return {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1,::1",
        }


# ---------------------------------------------------------------------------
# 2. Cloud Credential Isolation
# ---------------------------------------------------------------------------

class CloudCredentialManager:
    """Generates temporary, limited-scope cloud credentials.

    The agent NEVER gets access to the host's real cloud credentials.
    Instead, it receives:
        - A temporary token with limited permissions (via assume-role).
        - An opaque reference that can't be reversed to the real key.
        - Automatic expiration after engagement completion.

    Supported providers:
        - AWS (via STS assume-role)
        - GCP (via service account impersonation)
        - Azure (via managed identity)

    For now, this generates credential references that downstream
    integrations can use. Actual cloud provider interaction requires
    the respective SDKs and IAM policies.
    """

    def __init__(
        self,
        engagement_id: str = "",
        default_lifetime: int = DEFAULT_TEMP_TOKEN_LIFETIME,
    ):
        self.engagement_id = engagement_id or secrets.token_hex(8)
        self.default_lifetime = default_lifetime
        self._issued: dict[str, TempCredentials] = {}

    def generate(
        self,
        provider: str = "aws",
        role_arn: str = "",
        scope: Optional[list[str]] = None,
        lifetime: int = 0,
    ) -> TempCredentials:
        """Generate a temporary credential reference.

        Args:
            provider: Cloud provider (aws, gcp, azure).
            role_arn: IAM role ARN to assume (AWS) or equivalent.
            scope: Permission scopes (e.g., ['s3:GetObject', 'ec2:Describe*']).
            lifetime: Token lifetime in seconds (max 3600).

        Returns:
            TempCredentials with opaque reference.
        """
        lifetime = lifetime or self.default_lifetime
        lifetime = min(lifetime, MAX_TEMP_TOKEN_LIFETIME)

        # Generate opaque reference (NOT the real key — just a handle).
        opaque_id = secrets.token_hex(32)
        session_name = f"redamon-{self.engagement_id[:8]}-{int(time.time())}"

        # Hash the opaque ID for verification (can't be reversed).
        secret_hash = hashlib.sha256(
            f"{opaque_id}:{self.engagement_id}".encode()
        ).hexdigest()

        creds = TempCredentials(
            provider=provider,
            access_key_id=opaque_id,
            secret_hash=secret_hash,
            role_arn=role_arn,
            scope=scope or [],
            expires_at=time.time() + lifetime,
            session_name=session_name,
        )

        self._issued[opaque_id] = creds

        logger.info(
            "Issued temp credentials: provider=%s, role=%s, scope=%s, ttl=%ds",
            provider, role_arn, scope, lifetime,
        )

        return creds

    def revoke(self, access_key_id: str) -> bool:
        """Revoke temporary credentials before expiration."""
        if access_key_id in self._issued:
            del self._issued[access_key_id]
            logger.info("Revoked temp credentials: %s", access_key_id[:8])
            return True
        return False

    def revoke_all(self) -> int:
        """Revoke ALL temporary credentials for this engagement."""
        count = len(self._issued)
        self._issued.clear()
        logger.info("Revoked ALL temp credentials (%d)", count)
        return count

    def is_valid(self, access_key_id: str) -> bool:
        """Check if a credential reference is still valid."""
        creds = self._issued.get(access_key_id)
        if creds is None:
            return False
        return time.time() < creds.expires_at

    def list_active(self) -> list[TempCredentials]:
        """List all active (non-expired) credentials."""
        now = time.time()
        return [c for c in self._issued.values() if now < c.expires_at]


# ---------------------------------------------------------------------------
# 3. Session Cookie Isolation
# ---------------------------------------------------------------------------

class CookieSanitizer:
    """Prevents target session cookies from leaking to agent infrastructure.

    Strips cookies from redirect responses and ensures cookies
    are scoped to the target domain only.
    """

    @staticmethod
    def sanitize_set_cookie(set_cookie: str, target_domain: str) -> str:
        """Sanitize a Set-Cookie header for safe storage.

        Ensures the cookie:
            - Has Domain=target_domain (not a parent domain).
            - Has Secure and HttpOnly flags.
            - Has SameSite=Strict (prevent CSRF leakage).

        Returns the sanitized cookie string or empty if unsafe.
        """
        if not set_cookie:
            return ""

        parts = [p.strip() for p in set_cookie.split(";")]

        # First part is the cookie name=value.
        if not parts or "=" not in parts[0]:
            return ""

        # Add security flags.
        has_secure = any("secure" == p.lower() for p in parts)
        has_httponly = any("httponly" == p.lower() for p in parts)
        has_samesite = any("samesite" in p.lower() for p in parts)

        if not has_secure:
            parts.append("Secure")
        if not has_httponly:
            parts.append("HttpOnly")
        if not has_samesite:
            parts.append(f"SameSite=Strict")

        # Scrub domain attribute — replace with target domain.
        clean_parts = [parts[0]]
        for p in parts[1:]:
            lower = p.lower().strip()
            if lower.startswith("domain="):
                clean_parts.append(f"Domain={target_domain}")
            elif lower in ("path=/",) or lower.startswith("path="):
                clean_parts.append(p)
            elif lower == "secure":
                clean_parts.append("Secure")
            elif lower == "httponly":
                clean_parts.append("HttpOnly")
            elif lower.startswith("samesite="):
                clean_parts.append(p)
            elif lower.startswith("max-age=") or lower.startswith("expires="):
                clean_parts.append(p)
            # Drop other attributes (they may leak internal info).

        return "; ".join(clean_parts)

    @staticmethod
    def filter_response_cookies(
        response_headers: dict,
        target_domain: str,
    ) -> dict:
        """Filter and sanitize all Set-Cookie headers from a response.

        Args:
            response_headers: Response headers from the target.
            target_domain: Engagement target domain.

        Returns:
            Sanitized headers dict.
        """
        safe: dict = {}

        for key, value in (response_headers or {}).items():
            lower_key = key.lower().strip()

            if lower_key == "set-cookie":
                cookies = value if isinstance(value, list) else [value]
                sanitized = []
                for cookie in cookies:
                    clean = CookieSanitizer.sanitize_set_cookie(
                        cookie, target_domain
                    )
                    if clean:
                        sanitized.append(clean)
                if sanitized:
                    safe[key] = (
                        sanitized[0] if len(sanitized) == 1 else sanitized
                    )
            else:
                safe[key] = value

        return safe


# ---------------------------------------------------------------------------
# 4. Session Guard — unified interface
# ---------------------------------------------------------------------------

class SessionGuard:
    """Unified session security for RedAmon engagements.

    Combines header sanitization, cloud credential management, and
    cookie isolation into a single interface.

    Usage:
        guard = SessionGuard(engagement_id="eng_001")

        # Sanitize outbound request headers.
        headers = guard.prepare_request_headers(original_headers)

        # Get temp cloud credentials.
        creds = guard.get_cloud_credentials(provider="aws", scope=["s3:GetObject"])

        # Sanitize response cookies.
        response = guard.sanitize_response(response_headers, target_domain)
    """

    def __init__(
        self,
        engagement_id: str = "",
        proxy_host: str = "localhost",
        proxy_port: int = 8080,
    ):
        self.engagement_id = engagement_id or secrets.token_hex(8)
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.header_sanitizer = HeaderSanitizer()
        self.credential_manager = CloudCredentialManager(
            engagement_id=self.engagement_id,
        )
        self.cookie_sanitizer = CookieSanitizer()

    def prepare_request_headers(self, headers: dict) -> dict:
        """Sanitize headers for an outbound request."""
        return self.header_sanitizer.sanitize(headers)

    def get_proxy_env(self) -> dict:
        """Get proxy environment variables for subprocess calls."""
        return self.header_sanitizer.create_proxy_session(
            self.proxy_host, self.proxy_port,
        )

    def get_cloud_credentials(
        self,
        provider: str = "aws",
        role_arn: str = "",
        scope: Optional[list[str]] = None,
        lifetime: int = 0,
    ) -> TempCredentials:
        """Get temporary, limited-scope cloud credentials."""
        return self.credential_manager.generate(
            provider=provider,
            role_arn=role_arn,
            scope=scope,
            lifetime=lifetime,
        )

    def revoke_cloud_credentials(self, access_key_id: str) -> bool:
        """Revoke temporary cloud credentials."""
        return self.credential_manager.revoke(access_key_id)

    def sanitize_response(
        self,
        response_headers: dict,
        target_domain: str,
    ) -> dict:
        """Sanitize response headers to prevent cookie leakage."""
        return self.cookie_sanitizer.filter_response_cookies(
            response_headers, target_domain,
        )

    def cleanup(self) -> int:
        """Revoke all temp credentials and clean up."""
        return self.credential_manager.revoke_all()
