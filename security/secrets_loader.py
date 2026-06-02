"""
ComplianceLoop — Secrets Loader
================================
Unified interface for loading secrets from either:
  1. Environment variables (development, CI, simple deployments)
  2. HashiCorp Vault (production — USE_VAULT=true)

All other modules call get_secret() or load_secrets() rather than
reading os.environ directly. This means:
  - Switching from env vars to Vault requires no code changes elsewhere
  - Secrets are validated at startup with clear error messages
  - The secrets loader can enforce naming conventions and key separation

Vault setup (production):
  - USE_VAULT=true
  - VAULT_ADDR=http://vault:8200
  - VAULT_TOKEN=<token>  or use AppRole auth (see infra/vault/vault.hcl)
  - Secrets stored at: secret/data/complianceloop

Environment fallback (development):
  - USE_VAULT=false  (default)
  - All secrets read from .env file

Required secrets (validated at startup):
  - SERVER_HMAC_KEY    : 64-char hex (32 bytes) for audit HMAC signing
  - PAN_HMAC_KEY       : 64-char hex (32 bytes) for PAN hashing (must differ from above)
  - AES_KEY            : 64-char hex (32 bytes) for AES-256-GCM encryption
  - POSTGRES_PASSWORD  : PostgreSQL password
  - REDIS_PASSWORD     : Redis password
  - MINIO_SECRET_KEY   : MinIO secret key

Optional secrets:
  - SERVER_HMAC_KEY_PREVIOUS : Previous HMAC key during rotation window
  - SENDGRID_API_KEY         : Email delivery
  - DEMO_API_KEY             : Demo guideline editor protection
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ── Secret definitions ────────────────────────────────────────────────────────

# Secrets that MUST be present for the application to start
REQUIRED_SECRETS: list[str] = [
    "SERVER_HMAC_KEY",
    "PAN_HMAC_KEY",
    "AES_KEY",
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "MINIO_SECRET_KEY",
]

# Secrets that are optional (absence is logged as warning, not error)
OPTIONAL_SECRETS: list[str] = [
    "SERVER_HMAC_KEY_PREVIOUS",
    "SENDGRID_API_KEY",
    "DEMO_API_KEY",
    "GROQ_API_KEY",
    "VAULT_TOKEN",
    "GRAFANA_ADMIN_PASSWORD",
    "FLOWER_BASIC_AUTH",
]

# Secrets that must be DIFFERENT from each other (key separation enforcement)
MUST_DIFFER_PAIRS: list[tuple[str, str]] = [
    ("SERVER_HMAC_KEY", "PAN_HMAC_KEY"),
    ("SERVER_HMAC_KEY", "AES_KEY"),
    ("PAN_HMAC_KEY", "AES_KEY"),
]

# In-memory cache of loaded secrets
_secret_cache: dict[str, str] = {}
_loaded: bool = False


# ── Vault integration ─────────────────────────────────────────────────────────

def _load_from_vault() -> dict[str, str]:
    """
    Load all secrets from HashiCorp Vault KV v2.

    Requires:
        VAULT_ADDR  : Vault server URL (e.g. http://vault:8200)
        VAULT_TOKEN : Vault token with read access to VAULT_SECRET_PATH
        VAULT_MOUNT_PATH : KV mount path (default: secret)
        VAULT_SECRET_PATH : Path within mount (default: complianceloop)

    Returns:
        Dict of secret name → value.

    Raises:
        RuntimeError: If Vault is unreachable or auth fails.
    """
    try:
        import hvac  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "hvac package is required for Vault integration. "
            "Install with: pip install -r requirements/security.txt"
        ) from exc

    vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
    vault_token = os.environ.get("VAULT_TOKEN", "")
    mount_path = os.environ.get("VAULT_MOUNT_PATH", "secret")
    secret_path = os.environ.get("VAULT_SECRET_PATH", "complianceloop")

    if not vault_token:
        raise RuntimeError(
            "VAULT_TOKEN is not set. Cannot load secrets from Vault."
        )

    client = hvac.Client(url=vault_addr, token=vault_token)

    if not client.is_authenticated():
        raise RuntimeError(
            f"Vault authentication failed. Check VAULT_TOKEN and VAULT_ADDR ({vault_addr})."
        )

    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=secret_path,
            mount_point=mount_path,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to read secrets from Vault at {mount_path}/{secret_path}: {exc}"
        ) from exc

    secrets_data: dict[str, Any] = response.get("data", {}).get("data", {})
    if not secrets_data:
        raise RuntimeError(
            f"No data found at Vault path {mount_path}/{secret_path}. "
            "Ensure secrets have been initialised (see infra/vault/init_secrets.sh)."
        )

    logger.info(
        "Loaded %d secrets from Vault at %s/%s",
        len(secrets_data),
        mount_path,
        secret_path,
    )
    return {k: str(v) for k, v in secrets_data.items()}


def _load_from_environment() -> dict[str, str]:
    """
    Load secrets from environment variables.

    Returns:
        Dict of secret name → value for all env vars that are set.
    """
    all_secret_names = REQUIRED_SECRETS + OPTIONAL_SECRETS + ["SERVER_HMAC_KEY_PREVIOUS"]
    result: dict[str, str] = {}
    for name in all_secret_names:
        value = os.environ.get(name, "")
        if value:
            result[name] = value
    # Also load any other env vars that start with known prefixes
    for key, value in os.environ.items():
        if value and key not in result:
            result[key] = value
    return result


# ── Validation ────────────────────────────────────────────────────────────────

def _validate_secrets(secrets: dict[str, str]) -> None:
    """
    Validate that all required secrets are present and pass key separation checks.

    Raises:
        RuntimeError: If any required secret is missing or key separation is violated.
    """
    missing = [name for name in REQUIRED_SECRETS if not secrets.get(name)]
    if missing:
        raise RuntimeError(
            f"Missing required secrets: {', '.join(missing)}. "
            "Check your .env file or Vault configuration."
        )

    # Enforce key separation
    for key_a, key_b in MUST_DIFFER_PAIRS:
        val_a = secrets.get(key_a, "")
        val_b = secrets.get(key_b, "")
        if val_a and val_b and val_a == val_b:
            raise RuntimeError(
                f"SECURITY VIOLATION: {key_a} and {key_b} must be different keys. "
                "Using the same key for multiple purposes reduces security. "
                "Generate separate keys for each."
            )

    # Validate hex format and length for cryptographic keys
    crypto_keys = {
        "SERVER_HMAC_KEY": 32,
        "PAN_HMAC_KEY": 32,
        "AES_KEY": 32,
    }
    for key_name, expected_bytes in crypto_keys.items():
        value = secrets.get(key_name, "")
        if not value:
            continue
        try:
            key_bytes = bytes.fromhex(value)
        except ValueError:
            raise RuntimeError(
                f"{key_name} is not valid hex. "
                "Must be a hex string produced by: python -c \"import secrets; print(secrets.token_hex(32))\""
            ) from None
        if len(key_bytes) != expected_bytes:
            raise RuntimeError(
                f"{key_name} must be {expected_bytes} bytes ({expected_bytes * 2} hex chars). "
                f"Got {len(key_bytes)} bytes ({len(value)} hex chars)."
            )

    # Warn about optional secrets that are missing
    for name in OPTIONAL_SECRETS:
        if not secrets.get(name):
            logger.warning("Optional secret %s is not set.", name)


# ── Public API ────────────────────────────────────────────────────────────────

def load_secrets() -> None:
    """
    Load and validate all secrets.

    Called once at application startup (in api/main.py lifespan and
    workers/celery_app.py). Subsequent calls are no-ops (idempotent).

    Automatically uses Vault if USE_VAULT=true, otherwise uses env vars.

    Raises:
        RuntimeError: If required secrets are missing, malformed, or
                      key separation is violated.

    Side effects:
        - Populates the in-memory _secret_cache
        - Sets environment variables from Vault (so existing code
          that reads os.environ still works)
        - Calls invalidate_key_cache() on security modules to force
          re-load of cryptographic keys
    """
    global _loaded  # noqa: PLW0603

    if _loaded:
        return

    use_vault = os.environ.get("USE_VAULT", "false").lower() == "true"

    if use_vault:
        logger.info("Loading secrets from HashiCorp Vault.")
        secrets = _load_from_vault()
        # Inject Vault secrets into environment so existing code works
        for key, value in secrets.items():
            if key not in os.environ:
                os.environ[key] = value
    else:
        logger.info("Loading secrets from environment variables.")
        secrets = _load_from_environment()

    _validate_secrets(secrets)

    # Cache them
    _secret_cache.update(secrets)

    # Invalidate cryptographic key caches so they re-load from updated env
    try:
        from security.hmac_utils import invalidate_key_cache  # noqa: PLC0415
        from security.pan_handler import invalidate_pan_key_cache  # noqa: PLC0415
        invalidate_key_cache()
        invalidate_pan_key_cache()
    except ImportError:
        pass  # Fine during bootstrap before security module is fully initialised

    _loaded = True
    logger.info("Secrets loaded and validated successfully.")


def get_secret(name: str, default: str | None = None) -> str:
    """
    Retrieve a secret by name from the cache.

    If load_secrets() has not been called yet, attempts to load
    from environment as a fallback (useful in testing).

    Args:
        name: Secret name (e.g. "SERVER_HMAC_KEY").
        default: Value to return if secret is not found.
                 If None and secret is missing, raises KeyError.

    Returns:
        Secret value string.

    Raises:
        KeyError: If secret is not found and no default is provided.
    """
    # Try cache first
    if name in _secret_cache:
        return _secret_cache[name]

    # Try environment directly (fallback for tests / dev)
    env_value = os.environ.get(name, "")
    if env_value:
        return env_value

    if default is not None:
        return default

    raise KeyError(
        f"Secret '{name}' is not available. "
        "Ensure load_secrets() has been called at startup and the secret is configured."
    )


def reload_secrets() -> None:
    """
    Force re-load of all secrets.

    Called after key rotation (scripts/rotate_secrets.sh) to pick up
    new keys without restarting the application.

    Side effects:
        - Clears _secret_cache
        - Re-runs load_secrets()
        - Invalidates cryptographic key caches
    """
    global _loaded, _secret_cache  # noqa: PLW0603
    _loaded = False
    _secret_cache = {}

    # Invalidate caches in crypto modules
    try:
        from security.hmac_utils import invalidate_key_cache  # noqa: PLC0415
        from security.pan_handler import invalidate_pan_key_cache  # noqa: PLC0415
        invalidate_key_cache()
        invalidate_pan_key_cache()
    except ImportError:
        pass

    load_secrets()
    logger.info("Secrets reloaded successfully.")


def get_all_secret_names() -> list[str]:
    """Return list of all secret names currently in cache. Values are NOT returned."""
    return list(_secret_cache.keys())