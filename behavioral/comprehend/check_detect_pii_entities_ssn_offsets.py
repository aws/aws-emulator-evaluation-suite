"""detect-pii-entities-ssn-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-pii-entities-ssn-offsets"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectPiiEntities finds every SSN-typed entity in text carrying two distinct SSNs
    and reports BeginOffset/EndOffset for each that index back exactly to that SSN's own
    substring, not to the other occurrence's."""
    comprehend = ctx.client("comprehend")
    primary_ssn = "123-45-6789"
    joint_ssn = "987-65-4321"
    text = (
        f"Please update your records: primary SSN {primary_ssn}, "
        f"and the joint account SSN is {joint_ssn}."
    )
    resp = comprehend.detect_pii_entities(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert entities, "expected at least one PII entity"

    ssn_entities = sorted(
        (e for e in entities if e["Type"] == "SSN"), key=lambda e: e["BeginOffset"]
    )
    assert len(ssn_entities) == 2, f"expected exactly two SSN entities, got {entities}"

    for entity, expected_ssn in zip(ssn_entities, (primary_ssn, joint_ssn)):
        begin, end = entity["BeginOffset"], entity["EndOffset"]
        assert text[begin:end] == expected_ssn, (
            f"SSN offsets {begin}:{end} -> {text[begin:end]!r} != {expected_ssn!r} for text {text!r}"
        )
        assert 0.0 <= entity["Score"] <= 1.0, f"SSN score {entity['Score']} out of [0,1]"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
