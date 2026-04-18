"""AgentGuard NIST compliance library.

Provides:
- NIST 800-53 Rev 5.2 control definitions (controls_800_53.py)
- NIST AI RMF 1.0 function definitions (ai_rmf.py)
- NIST AI 600-1 Generative AI Profile risk areas (ai_rmf.py)
- Event-type to multi-framework control mappings (mappings.py)
- OWASP LLM Top 10 2025 vulnerability definitions (owasp_llm.py)
- MITRE ATLAS v5.4.0 tactic and technique definitions (mitre_atlas.py)
- CMMC 2.0 requirement stubs (cmmc.py)
"""

from __future__ import annotations

from agentguard.nist.controls_800_53 import NIST_800_53_VERSION
from agentguard.nist.ai_rmf import NIST_AI_600_1_VERSION, GenAIRiskArea, GEN_AI_RISK_AREAS
from agentguard.nist.owasp_llm import OWASP_LLM_VERSION, OWASP_LLM_TOP_10_2025
from agentguard.nist.mitre_atlas import MITRE_ATLAS_VERSION, AtlasTactic, ATLAS_TECHNIQUES
from agentguard.nist.cmmc import CMMC_VERSION, CmmcLevel
from agentguard.nist.mappings import FrameworkMapping, get_framework_mapping

__all__ = [
    "NIST_800_53_VERSION",
    "NIST_AI_600_1_VERSION",
    "OWASP_LLM_VERSION",
    "MITRE_ATLAS_VERSION",
    "CMMC_VERSION",
    "GenAIRiskArea",
    "GEN_AI_RISK_AREAS",
    "OWASP_LLM_TOP_10_2025",
    "AtlasTactic",
    "ATLAS_TECHNIQUES",
    "CmmcLevel",
    "FrameworkMapping",
    "get_framework_mapping",
]
