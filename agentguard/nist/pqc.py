"""Post-Quantum Cryptography (PQC) readiness assessment for AgentGuard (v0.3 stub).

Provides structured definitions for NIST-standardized PQC algorithms and a
readiness assessment function for AgentGuard's audit log signing key. Full
PQC-compliant signing (ML-DSA replacing Ed25519) is planned for AgentGuard v0.3.

Standards referenced:
- FIPS 203: ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
  https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
  https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
  https://csrc.nist.gov/pubs/fips/205/final
- NIST IR 8547: Transition to Post-Quantum Cryptography Standards

All three standards were finalized August 13, 2024.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum

# ---------------------------------------------------------------------------
# Federal PQC migration deadlines (NIST IR 8547)
# ---------------------------------------------------------------------------

# NIST IR 8547 federal civilian deadlines
FEDERAL_112BIT_DEPRECATION = date(2031, 12, 31)
"""Deadline to deprecate 112-bit quantum-vulnerable algorithms (NIST IR 8547)."""

FEDERAL_128BIT_DISALLOWED = date(2035, 12, 31)
"""Deadline to disallow 128-bit quantum-vulnerable algorithms (NIST IR 8547)."""

# NSA CNSA 2.0 National Security Systems deadlines
NSS_NEW_ACQUISITIONS_DEADLINE = date(2027, 1, 1)
"""All new NSS acquisitions must be CNSA 2.0 (PQC) compliant by this date."""

NSS_EXISTING_DEADLINE = date(2025, 12, 31)
"""Existing NSS must meet CNSA 1.0 or request waiver by this date (past)."""

NSS_FINAL_COMPLIANCE = date(2033, 12, 31)
"""Final mandatory CNSA 2.0 compliance for all NSS by this date."""


# ---------------------------------------------------------------------------
# PQC Algorithm Enum
# ---------------------------------------------------------------------------

class PqcAlgorithm(Enum):
    """NIST-standardized Post-Quantum Cryptographic algorithms (FIPS 203/204/205).

    ML-KEM variants (FIPS 203) are for key encapsulation (replacing RSA/ECDH).
    ML-DSA variants (FIPS 204) are for digital signatures (replacing Ed25519/ECDSA).
    SLH-DSA variants (FIPS 205) are hash-based signatures (no lattice dependency).

    The number suffix indicates the NIST security category:
    - Category 1: AES-128 equivalent
    - Category 3: AES-192 equivalent
    - Category 5: AES-256 equivalent
    """

    # FIPS 203 — ML-KEM (Key Encapsulation)
    ML_KEM_512 = "ML-KEM-512"       # Category 1, 128-bit classical security
    ML_KEM_768 = "ML-KEM-768"       # Category 3, 192-bit classical security
    ML_KEM_1024 = "ML-KEM-1024"     # Category 5, 256-bit classical security

    # FIPS 204 — ML-DSA (Digital Signature)
    ML_DSA_44 = "ML-DSA-44"         # Category 2, ~128-bit classical security
    ML_DSA_65 = "ML-DSA-65"         # Category 3, ~192-bit classical security
    ML_DSA_87 = "ML-DSA-87"         # Category 5, ~256-bit classical security

    # FIPS 205 — SLH-DSA (Hash-Based Signature)
    SLH_DSA_128S = "SLH-DSA-128s"   # Category 1, small signature variant
    SLH_DSA_128F = "SLH-DSA-128f"   # Category 1, fast signature variant
    SLH_DSA_192S = "SLH-DSA-192s"   # Category 3, small variant
    SLH_DSA_192F = "SLH-DSA-192f"   # Category 3, fast variant
    SLH_DSA_256S = "SLH-DSA-256s"   # Category 5, small variant
    SLH_DSA_256F = "SLH-DSA-256f"   # Category 5, fast variant

    # Current AgentGuard signing algorithm (pre-PQC, targeted for migration)
    ED25519 = "Ed25519"             # 128-bit classical, NOT quantum-resistant

    # Legacy algorithms — not PQC
    RSA_2048 = "RSA-2048"           # 112-bit classical, deprecated 2031
    RSA_3072 = "RSA-3072"           # 128-bit classical, disallowed 2035
    ECDSA_P256 = "ECDSA-P-256"      # 128-bit classical, disallowed 2035
    ECDSA_P384 = "ECDSA-P-384"      # 192-bit classical, disallowed 2035


# Set of algorithms that are PQC-compliant per FIPS 203/204/205
_PQC_COMPLIANT_ALGORITHMS: frozenset[PqcAlgorithm] = frozenset({
    PqcAlgorithm.ML_KEM_512,
    PqcAlgorithm.ML_KEM_768,
    PqcAlgorithm.ML_KEM_1024,
    PqcAlgorithm.ML_DSA_44,
    PqcAlgorithm.ML_DSA_65,
    PqcAlgorithm.ML_DSA_87,
    PqcAlgorithm.SLH_DSA_128S,
    PqcAlgorithm.SLH_DSA_128F,
    PqcAlgorithm.SLH_DSA_192S,
    PqcAlgorithm.SLH_DSA_192F,
    PqcAlgorithm.SLH_DSA_256S,
    PqcAlgorithm.SLH_DSA_256F,
})


# ---------------------------------------------------------------------------
# Readiness Assessment Dataclass
# ---------------------------------------------------------------------------

@dataclass
class PqcReadinessAssessment:
    """PQC readiness assessment for a cryptographic signing algorithm.

    Fields:
        signing_algorithm: The string name of the algorithm being assessed.
        is_pqc_ready: True if the algorithm is FIPS 203/204/205 compliant.
        migration_deadline: The federal deadline most relevant to this algorithm.
        gap_description: Human-readable description of the gap (if any) and
                         recommended migration path.
    """

    signing_algorithm: str
    is_pqc_ready: bool
    migration_deadline: date
    gap_description: str


def assess_audit_log_pqc_readiness(signing_key_type: str) -> PqcReadinessAssessment:
    """Assess whether the audit log signing algorithm is PQC-compliant.

    Checks if the provided signing key type matches a FIPS 203/204/205
    algorithm. Returns a readiness assessment with the applicable federal
    deadline and a migration recommendation if not compliant.

    Args:
        signing_key_type: String name of the signing algorithm in use.
                          Examples: "Ed25519", "ML-DSA-65", "RSA-2048".

    Returns:
        PqcReadinessAssessment with compliance status and migration guidance.
    """
    # Normalize input for comparison
    normalized = signing_key_type.strip()

    # Try to match to a known PqcAlgorithm by value
    matched_algorithm: PqcAlgorithm | None = None
    for algo in PqcAlgorithm:
        if algo.value.lower() == normalized.lower():
            matched_algorithm = algo
            break

    if matched_algorithm is None:
        # Unknown algorithm — treat as non-compliant, worst-case deadline
        return PqcReadinessAssessment(
            signing_algorithm=signing_key_type,
            is_pqc_ready=False,
            migration_deadline=FEDERAL_112BIT_DEPRECATION,
            gap_description=(
                f"Algorithm '{signing_key_type}' is not recognized as a NIST "
                f"PQC-standardized algorithm (FIPS 203/204/205). Migrate audit log "
                f"signing to ML-DSA-65 (FIPS 204) by the federal 112-bit deprecation "
                f"deadline ({FEDERAL_112BIT_DEPRECATION}). For NSS deployments, the "
                f"deadline is {NSS_NEW_ACQUISITIONS_DEADLINE} (CNSA 2.0)."
            ),
        )

    if matched_algorithm in _PQC_COMPLIANT_ALGORITHMS:
        return PqcReadinessAssessment(
            signing_algorithm=signing_key_type,
            is_pqc_ready=True,
            migration_deadline=FEDERAL_128BIT_DISALLOWED,  # No migration needed before this
            gap_description=(
                f"Algorithm '{signing_key_type}' is FIPS 203/204/205 compliant. "
                f"No migration required under current federal deadlines. "
                f"Review NIST IR 8547 updates annually."
            ),
        )

    # Non-PQC algorithm — determine which deadline applies
    if matched_algorithm in (PqcAlgorithm.RSA_2048,):
        deadline = FEDERAL_112BIT_DEPRECATION
        gap = (
            f"RSA-2048 provides 112-bit classical security and is quantum-vulnerable. "
            f"Federal agencies must deprecate 112-bit algorithms by {deadline} "
            f"(NIST IR 8547). Migrate to ML-DSA-65 (FIPS 204) for signature use. "
            f"NSS deadline: {NSS_NEW_ACQUISITIONS_DEADLINE}."
        )
    else:
        # Ed25519, RSA-3072, ECDSA variants — 128-bit classical, disallowed 2035
        deadline = FEDERAL_128BIT_DISALLOWED
        if matched_algorithm == PqcAlgorithm.ED25519:
            gap = (
                f"Ed25519 is the current AgentGuard audit log signing algorithm. "
                f"It provides 128-bit classical security but is NOT quantum-resistant. "
                f"Federal agencies must disallow 128-bit quantum-vulnerable algorithms "
                f"by {deadline} (NIST IR 8547). "
                f"Planned migration: ML-DSA-65 (FIPS 204) in AgentGuard v0.3. "
                f"NSS new acquisitions deadline: {NSS_NEW_ACQUISITIONS_DEADLINE}. "
                f"For NSS deployments requiring CNSA 2.0, migrate before "
                f"{NSS_NEW_ACQUISITIONS_DEADLINE}."
            )
        else:
            gap = (
                f"'{signing_key_type}' provides 128-bit classical security but is "
                f"quantum-vulnerable. Federal agencies must disallow these algorithms "
                f"by {deadline} (NIST IR 8547). Migrate to ML-DSA-65 (FIPS 204) "
                f"for signature use. NSS deadline: {NSS_NEW_ACQUISITIONS_DEADLINE}."
            )

    return PqcReadinessAssessment(
        signing_algorithm=signing_key_type,
        is_pqc_ready=False,
        migration_deadline=deadline,
        gap_description=gap,
    )


def is_pqc_compliant(algorithm_name: str) -> bool:
    """Convenience function: return True if the named algorithm is PQC-compliant."""
    assessment = assess_audit_log_pqc_readiness(algorithm_name)
    return assessment.is_pqc_ready
