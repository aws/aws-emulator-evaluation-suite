"""guardrail-checks-offsets-locate-entity-in-source-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "guardrail-checks-offsets-locate-entity-in-source-text"
GROUP = 'guardrail_checks'
SERVICES = ['bedrock-runtime']

_EMAIL = "jdoe@example.com"
_PHONE = "555-0100"
_PREAMBLE = "Booking confirmed."
_BODY = f"My email is {_EMAIL} and my phone is {_PHONE}."


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each detection's indexes and offsets slice its own entity out of the request text.
    The entities sit in message 0 block 1, so hardcoded 0/0 or concatenated-block offsets fail."""
    rt = ctx.client("bedrock-runtime")

    messages = [
        {"role": "user", "content": [{"text": _PREAMBLE}, {"text": _BODY}]},
        {"role": "assistant", "content": [{"text": "Noted."}]},
    ]
    resp = rt.invoke_guardrail_checks(
        messages=messages,
        checks={"sensitiveInformation": {"entities": [{"type": "EMAIL"}, {"type": "PHONE"}]}},
    )

    found = resp["results"]["sensitiveInformation"]["results"]
    assert {e["type"] for e in found} == {"EMAIL", "PHONE"}, (
        f"expected exactly EMAIL and PHONE detections, got "
        f"{sorted(e['type'] for e in found)!r} over {len(found)} entries"
    )
    assert resp["results"]["sensitiveInformation"]["truncated"] is False, (
        "a 70-character payload must not be reported as truncated"
    )

    expected = {"EMAIL": _EMAIL, "PHONE": _PHONE}
    for entry in found:
        addressed = messages[entry["messageIndex"]]["content"][entry["contentIndex"]]["text"]
        sliced = addressed[entry["beginOffset"]:entry["endOffset"]]
        assert sliced == expected[entry["type"]], (
            f"{entry['type']} detection addressed message {entry['messageIndex']} block "
            f"{entry['contentIndex']} offsets {entry['beginOffset']}:{entry['endOffset']}, which "
            f"slices {sliced!r} out of {addressed!r} -- expected {expected[entry['type']]!r}"
        )
        assert 0.0 < entry["confidenceScore"] <= 1.0, (
            f"{entry['type']} detection reported confidenceScore "
            f"{entry['confidenceScore']!r}, outside (0.0, 1.0]"
        )

    # Both entities live in the SECOND block of the FIRST message. A service that ignores the
    # addressing fields would report 0/0 and still slice something.
    assert {(e["messageIndex"], e["contentIndex"]) for e in found} == {(0, 1)}, (
        f"both entities are in message 0 block 1, but detections addressed "
        f"{sorted((e['messageIndex'], e['contentIndex']) for e in found)!r}"
    )

    # Billing units are counted, not merely present.
    assert resp["usage"]["sensitiveInformation"]["textUnits"] == 1, (
        f"three short blocks are one text unit; usage reported "
        f"{resp['usage']['sensitiveInformation']['textUnits']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
