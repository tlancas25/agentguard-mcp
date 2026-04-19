"""Configuration models for AgentGuard MCP.

Loads config from YAML file and environment variables.
Environment variables take precedence over YAML values.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class UpstreamServerConfig(BaseModel):
    """Configuration for a single upstream MCP server."""

    name: str
    transport: Literal["stdio", "http"] = "stdio"
    # stdio transport fields
    command: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    # http transport fields
    url: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    # optional per-server policy override
    policy_override: Optional[str] = None


class DetectorConfig(BaseModel):
    """Configuration for a single detector."""

    enabled: bool = False
    action: Literal["log", "deny"] = "log"
    score_threshold: float = 0.7


class DetectorsConfig(BaseModel):
    """Configuration block for all detectors."""

    prompt_injection: DetectorConfig = Field(default_factory=DetectorConfig)
    pii: DetectorConfig = Field(default_factory=DetectorConfig)
    secrets: DetectorConfig = Field(default_factory=lambda: DetectorConfig(enabled=True))
    tool_poisoning: DetectorConfig = Field(
        default_factory=lambda: DetectorConfig(enabled=True)
    )


class FederalConfig(BaseModel):
    """Federal-mode-specific configuration."""

    agency_id: str = ""
    system_name: str = ""
    impact_level: Literal["LOW", "MODERATE", "HIGH"] = "MODERATE"
    require_signing: bool = True
    siem_endpoint: str = ""
    siem_api_key: str = ""


class AgentGuardConfig(BaseModel):
    """Root configuration model for AgentGuard."""

    mode: Literal["dev", "federal"] = "dev"
    audit_db_path: Path = Path("./audit.db")
    signing_key: str = ""
    verify_key: str = ""
    gateway_api_keys: list[str] = Field(default_factory=list)
    gateway_bind_host: str = "127.0.0.1"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    upstream_servers: list[UpstreamServerConfig] = Field(default_factory=list)
    policy_bundles: list[str] = Field(default_factory=list)
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
    federal: FederalConfig = Field(default_factory=FederalConfig)

    @field_validator("audit_db_path", mode="before")
    @classmethod
    def coerce_path(cls, v: object) -> Path:
        """Coerce string to Path."""
        return Path(str(v))

    @classmethod
    def from_yaml(cls, config_path: Path) -> "AgentGuardConfig":
        """Load config from a YAML file, then overlay environment variables.

        Federal mode asserted in YAML cannot be downgraded by an environment
        variable. A downgrade attempt raises RuntimeError so callers and
        operators see the attempt instead of silently getting a permissive
        gateway (F4b).
        """
        data: dict = {}
        if config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}

        yaml_mode = data.get("mode")
        env_mode = os.environ.get("AGENTGUARD_MODE")
        if env_mode:
            if yaml_mode == "federal" and env_mode != "federal":
                raise RuntimeError(
                    "AGENTGUARD_MODE environment variable attempted to "
                    f"downgrade federal mode to '{env_mode}'. Refusing to "
                    "start. Remove the env var or change the YAML."
                )
            data["mode"] = env_mode

        env_db = os.environ.get("AGENTGUARD_AUDIT_DB")
        if env_db:
            data["audit_db_path"] = env_db

        env_signing = os.environ.get("AGENTGUARD_SIGNING_KEY")
        if env_signing:
            data["signing_key"] = env_signing

        env_verify = os.environ.get("AGENTGUARD_VERIFY_KEY")
        if env_verify:
            data["verify_key"] = env_verify

        env_log = os.environ.get("AGENTGUARD_LOG_LEVEL")
        if env_log:
            data["log_level"] = env_log

        env_api_keys = os.environ.get("AGENTGUARD_GATEWAY_API_KEYS")
        if env_api_keys:
            data["gateway_api_keys"] = [
                k.strip() for k in env_api_keys.split(",") if k.strip()
            ]

        env_bind = os.environ.get("AGENTGUARD_GATEWAY_BIND_HOST")
        if env_bind:
            data["gateway_bind_host"] = env_bind

        # Federal mode env overrides
        federal_data = data.get("federal", {})
        env_agency = os.environ.get("AGENTGUARD_AGENCY_ID")
        if env_agency:
            federal_data["agency_id"] = env_agency

        env_sysname = os.environ.get("AGENTGUARD_SYSTEM_NAME")
        if env_sysname:
            federal_data["system_name"] = env_sysname

        env_impact = os.environ.get("AGENTGUARD_IMPACT_LEVEL")
        if env_impact:
            federal_data["impact_level"] = env_impact

        if federal_data:
            data["federal"] = federal_data

        cfg = cls(**data)

        # Federal mode: force-enable every detector and close fail-open holes
        # that would otherwise survive a sparse YAML (F7).
        if cfg.mode == "federal":
            cfg.detectors.prompt_injection.enabled = True
            cfg.detectors.pii.enabled = True
            cfg.detectors.secrets.enabled = True
            cfg.detectors.tool_poisoning.enabled = True
            cfg.detectors.prompt_injection.action = "deny"
            cfg.detectors.pii.action = "deny"
            cfg.detectors.secrets.action = "deny"
            cfg.detectors.tool_poisoning.action = "deny"

        return cfg

    @classmethod
    def default_dev(cls) -> "AgentGuardConfig":
        """Return a minimal dev-mode config for use when no config file exists."""
        return cls(
            mode="dev",
            policy_bundles=["agentguard/policies/defaults/dev_mode.yaml"],
        )
