"""detect-entities-builtin-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-builtin-types"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntities finds the built-in PERSON and LOCATION entities in a document
    and their offsets self-consistently index back into the original text."""
    comprehend = ctx.client("comprehend")
    text = (
        "Amazon.com was founded by Jeff Bezos and is headquartered in Seattle, Washington."
    )
    resp = comprehend.detect_entities(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert entities, "expected at least one entity to be detected"

    for entity in entities:
        begin, end = entity["BeginOffset"], entity["EndOffset"]
        assert text[begin:end] == entity["Text"], "entity offsets must index back to Text"

    types = {e["Type"] for e in entities}
    assert "PERSON" in types, f"expected a PERSON entity, got types {sorted(types)!r}"
    assert "LOCATION" in types, f"expected a LOCATION entity, got types {sorted(types)!r}"

    person = next(e for e in entities if e["Type"] == "PERSON")
    assert "Bezos" in person["Text"], f"expected the PERSON entity to mention Bezos, got {person['Text']!r}"

    location = next(e for e in entities if e["Type"] == "LOCATION")
    assert "Seattle" in location["Text"] or "Washington" in location["Text"], (
        f"expected the LOCATION entity to mention Seattle or Washington, got {location['Text']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
