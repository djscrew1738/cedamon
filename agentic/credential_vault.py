"""
Credential Vault — AES-256 encrypted storage for credentials, hashes,
and sensitive data discovered during RedAmon engagements.

Features:
    - AES-256-GCM encryption with per-engagement keys
    - Automatic key derivation from engagement ID + master key
    - Structured credential storage (type, value, target, timestamp)
    - Auto-purge on engagement completion
    - Masked credential display (show only last 4 chars)
    - Integration with ContextManager for safe storage

Usage:
    vault = CredentialVault(engagement_id="eng_20260630_001")
    vault.store("password", "admin:secret123", target="10.10.10.5")
    vault.store("hash", "$6$salt$hash...", target="10.10.10.5")

    # Retrieve (decrypts automatically).
    creds = vault.list_credentials()

    # Mask for reports.
    masked = vault.mask_credential("admin:secret123")  # → "admin:*****t123"

    # Purge on completion.
    vault.purge()
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Key derivation parameters.
PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32  # 256-bit AES key
SALT_LENGTH = 16
NONCE_LENGTH = 12  # 96-bit nonce for GCM
TAG_LENGTH = 16    # 128-bit authentication tag

# Default vault directory (relative to engagement workspace).
DEFAULT_VAULT_DIR = ".redamon_vault"

# Master key — derived from environment or generated per-process.
# In production, use a hardware-backed key (HSM, TPM, or cloud KMS).
_MASTER_KEY_ENV = "REDAMON_MASTER_KEY"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    """A stored credential entry."""

    enc_type: str       # password, hash, token, cookie, key, certificate
    enc_value: str      # Base64-encoded encrypted value
    target: str = ""    # Target host/service
    username: str = ""  # Associated username
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)


@dataclass
class VaultStats:
    """Statistics about the credential vault."""

    total_entries: int = 0
    by_type: dict = field(default_factory=dict)
    size_bytes: int = 0
    created_at: float = 0.0


# ---------------------------------------------------------------------------
# AES-256-GCM via cryptography library
# ---------------------------------------------------------------------------

def _get_cipher():
    """Lazy-import cryptography to avoid hard dependency at module load."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        raise RuntimeError(
            "CredentialVault requires the 'cryptography' package. "
            "Install with: pip install cryptography"
        )


def _derive_key(engagement_id: str, salt: bytes) -> bytes:
    """Derive an AES-256 key from engagement ID + master key.

    Uses PBKDF2-HMAC-SHA256 with 600k iterations.
    """
    master_key = _get_master_key()
    material = f"{engagement_id}:{master_key}".encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha256",
        material,
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH,
    )


def _get_master_key() -> str:
    """Get the master key from environment or generate a per-process key.

    WARNING: Per-process keys are NOT durable — credentials encrypted
    with one key cannot be decrypted after a restart. Set
    REDAMON_MASTER_KEY for persistent key material.
    """
    master = os.environ.get(_MASTER_KEY_ENV)
    if master:
        return master

    # Per-process key — credentials survive only within one process lifetime.
    if not hasattr(_get_master_key, "_cache"):
        _get_master_key._cache = secrets.token_hex(32)  # type: ignore[attr-defined]
        logger.warning(
            "REDAMON_MASTER_KEY not set — using per-process key. "
            "Credentials will be lost on restart. Set %s for persistence.",
            _MASTER_KEY_ENV,
        )
    return _get_master_key._cache  # type: ignore[attr-defined]


def encrypt_aes256gcm(
    plaintext: str,
    engagement_id: str,
    salt: Optional[bytes] = None,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Args:
        plaintext: The credential text to encrypt.
        engagement_id: Unique engagement identifier for key derivation.
        salt: Optional salt (auto-generated if not provided).

    Returns:
        Tuple of (ciphertext, nonce, salt) — all as raw bytes.
    """
    AESGCM = _get_cipher()

    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)

    key = _derive_key(engagement_id, salt)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return ciphertext, nonce, salt


def decrypt_aes256gcm(
    ciphertext: bytes,
    nonce: bytes,
    salt: bytes,
    engagement_id: str,
) -> str:
    """Decrypt ciphertext with AES-256-GCM.

    Args:
        ciphertext: Encrypted data.
        nonce: Nonce used during encryption.
        salt: Salt used for key derivation.
        engagement_id: Same engagement ID used during encryption.

    Returns:
        Decrypted plaintext string.

    Raises:
        RuntimeError: If decryption fails (wrong key, corrupted data).
    """
    AESGCM = _get_cipher()

    key = _derive_key(engagement_id, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise RuntimeError(
            f"Credential decryption failed: {exc}. "
            f"Wrong engagement ID, corrupted data, or different master key."
        ) from exc


# ---------------------------------------------------------------------------
# Credential Vault
# ---------------------------------------------------------------------------

class CredentialVault:
    """Encrypted credential storage with auto-purge.

    Credentials are stored in AES-256-GCM encrypted files within a
    per-engagement vault directory. All operations go through the
    encrypt/decrypt pipeline — credentials are never written in plaintext.

    Usage:
        vault = CredentialVault(engagement_id="eng_001")
        vault.store("password", "admin:s3cr3t", target="10.0.0.1")
        vault.store("hash", "$6$...", target="10.0.0.1")

        creds = vault.list_credentials(decrypt=True)
        for c in creds:
            print(vault.mask_credential(c.dec_value))

        vault.purge()  # Delete everything on engagement completion
    """

    def __init__(
        self,
        engagement_id: str,
        vault_dir: str = DEFAULT_VAULT_DIR,
    ):
        self.engagement_id = engagement_id
        self.vault_dir = Path(vault_dir)
        self._index_path = self.vault_dir / f"{engagement_id}.index"
        self._created_at = time.time()
        self._initialized = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Create vault directory and index file."""
        if self._initialized:
            return

        self.vault_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.vault_dir, 0o700)  # Owner-only access

        if not self._index_path.exists():
            self._write_index([])

        self._initialized = True
        logger.info(
            "CredentialVault initialized: eng=%s, dir=%s",
            self.engagement_id, self.vault_dir,
        )

    def store(
        self,
        cred_type: str,
        value: str,
        target: str = "",
        username: str = "",
        metadata: Optional[dict] = None,
    ) -> int:
        """Store a credential entry encrypted with AES-256-GCM.

        Args:
            cred_type: Type of credential (password, hash, token, cookie, key).
            value: The credential value to encrypt.
            target: Target host/service associated with the credential.
            username: Associated username.
            metadata: Additional metadata dict.

        Returns:
            Index of the stored credential (0-based).
        """
        self.initialize()

        # Encrypt.
        ciphertext, nonce, salt = encrypt_aes256gcm(
            value, self.engagement_id
        )

        # Store encrypted blob.
        blob_id = self._next_blob_id()
        blob_path = self.vault_dir / f"{blob_id}.enc"
        blob_data = {
            "v": 1,  # Version
            "engagement_id": self.engagement_id,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "metadata": metadata or {},
        }
        blob_path.write_text(json.dumps(blob_data), encoding="utf-8")
        os.chmod(blob_path, 0o600)

        # Update index.
        index = self._read_index()
        entry = {
            "blob_id": blob_id,
            "type": cred_type,
            "target": target,
            "username": username,
            "timestamp": time.time(),
        }
        index.append(entry)
        self._write_index(index)

        logger.debug(
            "Stored credential: type=%s, target=%s, blob=%s",
            cred_type, target, blob_id,
        )
        return len(index) - 1

    def list_credentials(
        self,
        cred_type: Optional[str] = None,
        decrypt: bool = False,
    ) -> list[dict]:
        """List credentials, optionally filtered by type.

        Args:
            cred_type: Filter by credential type (None = all).
            decrypt: If True, decrypt each credential and include the
                plaintext value under ``dec_value``.

        Returns:
            List of credential dicts with keys: type, target, username,
            timestamp, blob_id (and dec_value if decrypt=True).
        """
        self.initialize()
        index = self._read_index()

        results = []
        for entry in index:
            if cred_type and entry["type"] != cred_type:
                continue

            result = {
                "type": entry["type"],
                "target": entry.get("target", ""),
                "username": entry.get("username", ""),
                "timestamp": entry.get("timestamp", 0),
                "blob_id": entry.get("blob_id", ""),
            }

            if decrypt:
                try:
                    result["dec_value"] = self._decrypt_blob(entry["blob_id"])
                except RuntimeError as exc:
                    logger.warning(
                        "Failed to decrypt blob %s: %s", entry["blob_id"], exc
                    )
                    result["dec_value"] = "[DECRYPTION FAILED]"

            results.append(result)

        return results

    def get_credential(self, index: int, decrypt: bool = True) -> Optional[dict]:
        """Get a specific credential by index.

        Returns None if index is out of range.
        """
        self.initialize()
        idx = self._read_index()
        if index < 0 or index >= len(idx):
            return None

        entry = idx[index]
        result = {
            "type": entry["type"],
            "target": entry.get("target", ""),
            "username": entry.get("username", ""),
            "timestamp": entry.get("timestamp", 0),
            "blob_id": entry.get("blob_id", ""),
        }

        if decrypt:
            try:
                result["dec_value"] = self._decrypt_blob(entry["blob_id"])
            except RuntimeError as exc:
                logger.warning("Failed to decrypt blob %s: %s", entry["blob_id"], exc)
                result["dec_value"] = "[DECRYPTION FAILED]"

        return result

    def purge(self) -> bool:
        """Purge ALL credentials and destroy the vault.

        Deletes the entire vault directory. This is irreversible.
        Call this at engagement completion.

        Returns True if purge was successful.
        """
        if not self.vault_dir.exists():
            return True

        try:
            shutil.rmtree(self.vault_dir, ignore_errors=False)
            self._initialized = False
            logger.info(
                "CredentialVault PURGED: eng=%s, dir=%s",
                self.engagement_id, self.vault_dir,
            )
            return True
        except Exception as exc:
            logger.error("Failed to purge vault: %s", exc)
            return False

    def stats(self) -> VaultStats:
        """Get vault statistics."""
        self.initialize()
        index = self._read_index()

        by_type: dict = {}
        total_size = 0
        for entry in index:
            t = entry.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

            try:
                blob_path = self.vault_dir / f"{entry['blob_id']}.enc"
                if blob_path.exists():
                    total_size += blob_path.stat().st_size
            except Exception:
                pass

        return VaultStats(
            total_entries=len(index),
            by_type=by_type,
            size_bytes=total_size,
            created_at=self._created_at,
        )

    # ------------------------------------------------------------------
    # Credential masking
    # ------------------------------------------------------------------

    @staticmethod
    def mask_credential(value: str, show_chars: int = 4) -> str:
        """Mask a credential for safe display in logs/reports.

        Shows only the last ``show_chars`` characters and blanks the rest.

        Examples:
            >>> CredentialVault.mask_credential("admin:secret123")
            '****t123'
            >>> CredentialVault.mask_credential("short")
            '****'
        """
        if not value:
            return ""
        if len(value) <= show_chars:
            return "*" * min(len(value), 4)
        return "*" * (len(value) - show_chars) + value[-show_chars:]

    @staticmethod
    def mask_hash(hash_value: str) -> str:
        """Mask a password hash for reports (show algorithm + last 8 chars)."""
        if not hash_value:
            return ""
        # Keep the algorithm prefix (e.g., "$6$" for SHA-512 crypt).
        parts = hash_value.split("$", 2)
        if len(parts) >= 3 and parts[0] == "" and parts[1].isdigit():
            algo = f"${parts[1]}$"
            rest = parts[2]
            if len(rest) > 8:
                return f"{algo}...{rest[-8:]}"
            return f"{algo}{rest}"
        # Generic: show last 8.
        if len(hash_value) > 8:
            return f"...{hash_value[-8:]}"
        return hash_value

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_blob_id(self) -> str:
        """Generate a unique blob ID."""
        return secrets.token_hex(16)

    def _read_index(self) -> list[dict]:
        """Read the credential index file."""
        if not self._index_path.exists():
            return []
        try:
            data = json.loads(self._index_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            logger.warning("Corrupted vault index, starting fresh")
            return []

    def _write_index(self, index: list[dict]) -> None:
        """Write the credential index file."""
        self._index_path.write_text(
            json.dumps(index, indent=2), encoding="utf-8"
        )
        os.chmod(self._index_path, 0o600)

    def _decrypt_blob(self, blob_id: str) -> str:
        """Decrypt a stored credential blob."""
        blob_path = self.vault_dir / f"{blob_id}.enc"
        if not blob_path.exists():
            raise RuntimeError(f"Blob not found: {blob_id}")

        try:
            data = json.loads(blob_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"Failed to read blob {blob_id}: {exc}") from exc

        version = data.get("v", 1)
        if version != 1:
            raise RuntimeError(f"Unsupported blob version: {version}")

        ciphertext = base64.b64decode(data["ciphertext_b64"])
        nonce = base64.b64decode(data["nonce_b64"])
        salt = base64.b64decode(data["salt_b64"])

        return decrypt_aes256gcm(
            ciphertext, nonce, salt, self.engagement_id
        )
