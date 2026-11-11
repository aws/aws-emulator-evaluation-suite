"""detect-pii-entities-locates-ssn-with-correct-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-pii-entities-locates-ssn-with-correct-offsets"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectPiiEntities finds an SSN-typed entity with offsets exactly bounding the digit sequence."""
    comprehend = ctx.client("comprehend")
    ssn = "123-45-6789"
    text = f"Please update your records: SSN {ssn}, thank you."
    resp = comprehend.detect_pii_entities(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert entities, "expected at least one PII entity"

    ssn_entities = [e for e in entities if e["Type"] == "SSN"]
    assert len(ssn_entities) == 1, (
        f"expected exactly one SSN entity, got types {[e['Type'] for e in entities]!r}"
    )

    expected_begin = text.index(ssn)
    expected_end = expected_begin + len(ssn)
    entity = ssn_entities[0]
    assert (entity["BeginOffset"], entity["EndOffset"]) == (expected_begin, expected_end), (
        f"SSN offsets {entity['BeginOffset']}:{entity['EndOffset']} != "
        f"expected {expected_begin}:{expected_end} for text {text!r}"
    )
    assert 0.0 <= entity["Score"] <= 1.0, f"Score {entity['Score']!r} not in [0.0, 1.0]"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
