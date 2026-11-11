"""contains-pii-entities-agrees-with-detect-pii-entities."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "contains-pii-entities-agrees-with-detect-pii-entities"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The boolean/coarse ContainsPiiEntities labels agree with the detailed DetectPiiEntities
    entity types for the same document -- the two related PII operations must not disagree about
    which PII categories are present."""
    comprehend = ctx.client("comprehend")
    text = (
        "Contact John at john.doe@example.com or call him about SSN 123-45-6789 "
        "regarding his account."
    )

    contains_resp = comprehend.contains_pii_entities(Text=text, LanguageCode="en")
    detect_resp = comprehend.detect_pii_entities(Text=text, LanguageCode="en")

    contains_names = {label["Name"] for label in contains_resp["Labels"]}
    detect_types = {entity["Type"] for entity in detect_resp["Entities"]}

    assert contains_names, "expected ContainsPiiEntities to report at least one category"
    assert detect_types, "expected DetectPiiEntities to report at least one entity"

    # Every category ContainsPiiEntities claims is present must be backed by at least one
    # DetectPiiEntities entity of that same type, and vice versa.
    assert contains_names == detect_types, (
        f"ContainsPiiEntities categories {contains_names!r} disagree with "
        f"DetectPiiEntities types {detect_types!r} for the same document"
    )
    assert "EMAIL" in detect_types, f"expected EMAIL among DetectPiiEntities types, got {detect_types!r}"
    assert "SSN" in detect_types, f"expected SSN among DetectPiiEntities types, got {detect_types!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
