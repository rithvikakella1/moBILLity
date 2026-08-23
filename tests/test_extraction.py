"""Unit tests for LLM response parsing and the confidence threshold.

This is the most logic-dense function in the codebase and previously had no
coverage. It runs against adversarial model output, so it must never raise.
"""
import json

import pytest

import app as extraction_app

parse = extraction_app._parse_llm_response
THRESHOLD = extraction_app.CONFIRMED_CONFIDENCE_THRESHOLD


def _code(code="E11.9", confidence=0.95, **extra):
    payload = {
        "type": "Diagnosis",
        "code_type": "ICD-10-CM",
        "code": code,
        "description": "Type 2 diabetes mellitus without complications",
        "reasoning": "Documented in assessment.",
        "confidence": confidence,
        "documentation_strength": "strong",
        "billing_priority": "primary",
    }
    payload.update(extra)
    return payload


class TestWellFormedOutput:
    def test_plain_json_object(self):
        result = parse(json.dumps({"confirmed_codes": [_code()], "suggested_codes": []}))
        assert len(result["confirmed_codes"]) == 1
        assert result["confirmed_codes"][0]["code"] == "E11.9"

    def test_markdown_fences_are_stripped(self):
        body = json.dumps({"confirmed_codes": [_code()], "suggested_codes": []})
        result = parse(f"```json\n{body}\n```")
        assert len(result["confirmed_codes"]) == 1

    def test_prose_around_the_object_is_discarded(self):
        body = json.dumps({"confirmed_codes": [_code()], "suggested_codes": []})
        result = parse(f"Here are the codes I found:\n{body}\nLet me know if you need more.")
        assert len(result["confirmed_codes"]) == 1

    def test_a_bare_array_is_treated_as_confirmed_codes(self):
        result = parse(json.dumps([_code()]))
        assert len(result["confirmed_codes"]) == 1
        assert result["suggested_codes"] == []


class TestConfidenceThreshold:
    def test_codes_at_the_threshold_stay_confirmed(self):
        result = parse(json.dumps({"confirmed_codes": [_code(confidence=THRESHOLD)]}))
        assert len(result["confirmed_codes"]) == 1
        assert result["suggested_codes"] == []

    def test_codes_below_the_threshold_are_downgraded(self):
        result = parse(json.dumps({"confirmed_codes": [_code(confidence=THRESHOLD - 0.01)]}))
        assert result["confirmed_codes"] == []
        assert len(result["suggested_codes"]) == 1
        assert "below threshold" in result["suggested_codes"][0]["reason_suggested"]

    def test_a_downgraded_code_keeps_its_identity(self):
        result = parse(json.dumps({"confirmed_codes": [_code(code="J45.909", confidence=0.4)]}))
        downgraded = result["suggested_codes"][0]
        assert downgraded["code"] == "J45.909"
        assert downgraded["code_type"] == "ICD-10-CM"
        assert downgraded["documentation_needed"]

    def test_downgrades_append_to_existing_suggestions(self):
        payload = {
            "confirmed_codes": [_code(confidence=0.2)],
            "suggested_codes": [{"code": "99490", "code_type": "CPT"}],
        }
        result = parse(json.dumps(payload))
        assert len(result["suggested_codes"]) == 2

    @pytest.mark.parametrize("bad", ["high", None, "", [], {}])
    def test_non_numeric_confidence_is_downgraded_not_fatal(self, bad):
        result = parse(json.dumps({"confirmed_codes": [_code(confidence=bad)]}))
        assert result["confirmed_codes"] == []
        assert len(result["suggested_codes"]) == 1

    def test_missing_confidence_is_treated_as_zero(self):
        code = _code()
        del code["confidence"]
        result = parse(json.dumps({"confirmed_codes": [code]}))
        assert result["confirmed_codes"] == []


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "I could not find any codes.",
            "{ this is not json",
            '{"confirmed_codes": [',
            "null",
            "```json\n```",
        ],
    )
    def test_garbage_never_raises(self, text):
        result = parse(text)
        assert isinstance(result["confirmed_codes"], list)
        assert isinstance(result["suggested_codes"], list)

    def test_missing_keys_default_to_empty_lists(self):
        result = parse(json.dumps({"something_else": True}))
        assert result["confirmed_codes"] == []
        assert result["suggested_codes"] == []

    def test_unparseable_text_is_preserved_for_debugging(self):
        result = parse("total nonsense, no braces here")
        assert result.get("raw") == "total nonsense, no braces here"


class TestExtractionEndpoint:
    def test_empty_note_is_rejected(self, signed_in):
        client, headers, _ = signed_in("extract-empty@example.com")
        response = client.post("/api/extract", headers=headers, json={"note": "   "})
        assert response.status_code == 400

    def test_provider_errors_do_not_leak_internals(self, signed_in, monkeypatch):
        """The client must never see SDK exception text."""
        client, headers, _ = signed_in("extract-error@example.com")

        def _boom(_note):
            raise RuntimeError("sk-secret-key-leaked org_id=org-12345 request_id=req_abc")

        monkeypatch.setattr(extraction_app, "extract_medical_codes", _boom)
        response = client.post("/api/extract", headers=headers, json={"note": "Patient note"})

        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "sk-secret" not in detail
        assert "org-12345" not in detail
        assert "req_abc" not in detail
        assert "reference" in detail.lower()

    def test_a_successful_extraction_returns_the_parsed_result(self, signed_in, monkeypatch):
        client, headers, _ = signed_in("extract-ok@example.com")
        monkeypatch.setattr(
            extraction_app, "extract_medical_codes",
            lambda note: {"confirmed_codes": [_code()], "suggested_codes": []},
        )
        response = client.post("/api/extract", headers=headers, json={"note": "Patient note"})
        assert response.status_code == 200
        assert response.json()["result"]["confirmed_codes"][0]["code"] == "E11.9"


class TestIcd10Validation:
    """Non-billable parent codes must never reach confirmed.

    M54.5 and N18.3 were subdivided in FY2022. A payer rejects them outright,
    so shipping one as "ready to bill" is worse than a merely debatable code.
    """

    def test_subdivided_parent_is_not_billable(self):
        assert not extraction_app.icd10_is_billable("M54.5")
        assert not extraction_app.icd10_is_billable("N18.3")

    def test_complete_code_is_billable(self):
        assert extraction_app.icd10_is_billable("M54.50")
        assert extraction_app.icd10_is_billable("E11.9")
        assert extraction_app.icd10_is_billable("S80.01XA")

    def test_formatting_is_ignored(self):
        assert extraction_app.icd10_is_billable("e1142")
        assert extraction_app.icd10_is_billable(" E11.42 ")

    def test_unbillable_code_is_demoted_not_dropped(self):
        """The coder needs to see it -- it is usually the right family."""
        result = extraction_app._apply_confidence_threshold({
            "confirmed_codes": [
                {"code_type": "ICD-10-CM", "code": "M54.5", "confidence": 0.99},
                {"code_type": "ICD-10-CM", "code": "E11.9", "confidence": 0.99},
            ],
            "suggested_codes": [],
        })
        assert [c["code"] for c in result["confirmed_codes"]] == ["E11.9"]
        assert [c["code"] for c in result["suggested_codes"]] == ["M54.5"]

    def test_other_systems_pass_through(self):
        """CPT and HCPCS are not checked against the ICD-10 list."""
        result = extraction_app._apply_confidence_threshold({
            "confirmed_codes": [
                {"code_type": "CPT", "code": "99213", "confidence": 0.99},
                {"code_type": "HCPCS", "code": "L1902", "confidence": 0.99},
            ],
            "suggested_codes": [],
        })
        assert len(result["confirmed_codes"]) == 2

    def test_missing_code_file_degrades_permissively(self, monkeypatch):
        """A missing data file must not reject every code."""
        monkeypatch.setattr(extraction_app, "_ICD10_CODES", set())
        assert extraction_app.icd10_is_billable("M54.5")
