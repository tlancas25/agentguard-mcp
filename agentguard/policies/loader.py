"""Policy bundle loader and validator for AgentGuard."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml

from agentguard.policy_engine import PolicyBundle, PolicyEngine
from agentguard.modes import Mode

logger = logging.getLogger(__name__)


def load_bundle(path: Path) -> Optional[PolicyBundle]:
    """Load a single policy bundle YAML file.

    Args:
        path: Path to the policy YAML file.

    Returns:
        PolicyBundle if loaded successfully, None on error.
    """
    if not path.exists():
        logger.warning("Policy bundle not found: %s", path)
        return None

    try:
        bundle = PolicyBundle.from_yaml(path)
        logger.info("Loaded policy bundle: %s", bundle.name)
        return bundle
    except yaml.YAMLError as e:
        logger.error("YAML parse error in %s: %s", path, e)
        return None
    except Exception as e:
        logger.error("Failed to load policy bundle %s: %s", path, e)
        return None


def load_bundles(paths: list[str]) -> list[PolicyBundle]:
    """Load multiple policy bundle files.

    Args:
        paths: List of file path strings.

    Returns:
        List of successfully loaded PolicyBundle objects.
    """
    bundles: list[PolicyBundle] = []
    for path_str in paths:
        bundle = load_bundle(Path(path_str))
        if bundle is not None:
            bundles.append(bundle)
    return bundles


def validate_bundle_file(path: Path, mode: Mode = Mode.DEV) -> tuple[bool, list[str]]:
    """Validate a policy bundle YAML file.

    Args:
        path: Path to the policy YAML file.
        mode: Operating mode to use for validation context.

    Returns:
        Tuple of (is_valid, error_messages).
    """
    engine = PolicyEngine(mode=mode)
    errors = engine.validate_bundle_file(path)
    return (len(errors) == 0, errors)
