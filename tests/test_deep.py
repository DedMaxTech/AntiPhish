from antiphish.deep import _json_object


def test_deep_json_parser_removes_thinking():
    value = '<think>ignore</think>\n{"credential_request": false, "payment_change": true, "impersonation": false, "rationale": "changed bank details"}'
    parsed = _json_object(value)
    assert parsed is not None
    assert parsed["payment_change"] is True


def test_deep_json_parser_fails_closed_as_evidence():
    assert _json_object("not json") is None
