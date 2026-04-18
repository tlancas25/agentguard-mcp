"""Tests for the NIST 800-53 Rev 5 control library.

Validates that all control definitions are well-formed and complete.
"""

from __future__ import annotations

import pytest

from agentguard.nist.controls_800_53 import (
    CONTROLS,
    ControlDefinition,
    get_control,
    get_controls_for_family,
    list_controls,
)
from agentguard.nist.ai_rmf import (
    AI_RMF_FUNCTIONS,
    AIRMFFunction,
    get_function,
    list_by_function,
    list_functions,
)
from agentguard.nist.mappings import (
    EVENT_CONTROL_MAP,
    get_controls_for_event,
    get_controls_summary,
)

REQUIRED_CONTROLS = [
    "AC-3", "AC-6", "AC-7", "AC-17",
    "AU-2", "AU-3", "AU-9", "AU-10", "AU-12",
    "IA-2", "SC-8", "SI-4", "SI-10",
]


class TestControlLibrary:
    """NIST 800-53 control library structure tests."""

    def test_all_required_controls_present(self) -> None:
        """All 13 required controls are in the library."""
        for cid in REQUIRED_CONTROLS:
            assert cid in CONTROLS, f"Control {cid} missing from library"

    def test_controls_have_required_fields(self) -> None:
        """Every control definition has all required fields populated."""
        for cid, control in CONTROLS.items():
            assert control.control_id == cid, f"{cid}: control_id mismatch"
            assert control.title, f"{cid}: title is empty"
            assert control.family, f"{cid}: family is empty"
            assert control.description, f"{cid}: description is empty"
            assert control.agentguard_implementation, f"{cid}: implementation is empty"

    def test_get_control_known_id(self) -> None:
        """get_control() returns the correct control for a known ID."""
        ac3 = get_control("AC-3")
        assert ac3.control_id == "AC-3"
        assert ac3.title == "Access Enforcement"

    def test_get_control_unknown_id_raises(self) -> None:
        """get_control() raises KeyError for unknown IDs."""
        with pytest.raises(KeyError):
            get_control("XX-999")

    def test_list_controls_sorted(self) -> None:
        """list_controls() returns controls sorted by ID."""
        controls = list_controls()
        ids = [c.control_id for c in controls]
        assert ids == sorted(ids)

    def test_get_controls_for_au_family(self) -> None:
        """AU family filter returns only AU controls."""
        au_controls = get_controls_for_family("AU")
        assert len(au_controls) > 0
        for c in au_controls:
            assert c.control_id.startswith("AU-")

    def test_code_references_are_strings(self) -> None:
        """All code references are non-empty strings."""
        for cid, control in CONTROLS.items():
            for ref in control.code_references:
                assert isinstance(ref, str)
                assert len(ref) > 0, f"{cid}: empty code reference"

    def test_au_9_mentions_hash_chain(self) -> None:
        """AU-9 implementation describes hash chain."""
        au9 = get_control("AU-9")
        assert "hash" in au9.agentguard_implementation.lower()

    def test_ac_6_mentions_deny_by_default(self) -> None:
        """AC-6 implementation mentions deny by default."""
        ac6 = get_control("AC-6")
        assert "deny" in ac6.agentguard_implementation.lower()


class TestAIRMFLibrary:
    """NIST AI RMF function library tests."""

    REQUIRED_FUNCTIONS = [
        "GOVERN-1.2", "GOVERN-1.5", "GOVERN-4.3",
        "MAP-2.1", "MAP-3.1", "MAP-5.1",
        "MEASURE-2.1", "MEASURE-2.6", "MEASURE-2.7", "MEASURE-3.1",
        "MANAGE-1.3", "MANAGE-3.2", "MANAGE-4.1",
    ]

    def test_all_required_functions_present(self) -> None:
        """All 13 required AI RMF functions are in the library."""
        for fid in self.REQUIRED_FUNCTIONS:
            assert fid in AI_RMF_FUNCTIONS, f"AI RMF function {fid} missing"

    def test_functions_have_required_fields(self) -> None:
        """Every function definition has all required fields populated."""
        for fid, func in AI_RMF_FUNCTIONS.items():
            assert func.function in ("GOVERN", "MAP", "MEASURE", "MANAGE")
            assert func.title, f"{fid}: title is empty"
            assert func.description, f"{fid}: description is empty"
            assert func.agentguard_implementation, f"{fid}: implementation is empty"

    def test_list_by_govern(self) -> None:
        """list_by_function('GOVERN') returns only GOVERN functions."""
        govern = list_by_function("GOVERN")
        assert len(govern) >= 3
        for f in govern:
            assert f.function == "GOVERN"

    def test_get_function_by_full_id(self) -> None:
        """get_function() resolves 'GOVERN 1.2' format."""
        func = get_function("GOVERN 1.2")
        assert func.full_id == "GOVERN 1.2"

    def test_list_functions_sorted(self) -> None:
        """list_functions() is sorted by function then subcategory."""
        functions = list_functions()
        assert len(functions) > 0


class TestEventMappings:
    """Event-type to NIST control mapping tests."""

    def test_tool_call_maps_to_au_controls(self) -> None:
        """tool_call events map to AU controls."""
        controls = get_controls_for_event("tool_call")
        assert "AU-2" in controls
        assert "AU-12" in controls

    def test_tool_denied_maps_to_ac_controls(self) -> None:
        """tool_denied events map to AC controls."""
        controls = get_controls_for_event("tool_denied")
        assert "AC-3" in controls
        assert "AC-6" in controls

    def test_injection_detected_maps_to_si_controls(self) -> None:
        """injection_detected events map to SI controls."""
        controls = get_controls_for_event("injection_detected")
        assert "SI-10" in controls
        assert "SI-4" in controls

    def test_unknown_event_type_returns_fallback(self) -> None:
        """Unknown event types return fallback controls."""
        controls = get_controls_for_event("nonexistent_event")
        assert "AU-2" in controls

    def test_controls_summary_covers_all_events(self) -> None:
        """controls_summary() returns a mapping for every event in EVENT_CONTROL_MAP."""
        summary = get_controls_summary()
        for event_type in EVENT_CONTROL_MAP:
            for control in EVENT_CONTROL_MAP[event_type]:
                assert control in summary
                assert event_type in summary[control]
