"""detect-entities-identifies-person-and-location-with-consistent-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-identifies-person-and-location-with-consistent-offsets"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntities finds a PERSON and a LOCATION in a documented-example sentence, and every
    returned offset pair slices back to exactly the reported entity text."""
    comprehend = ctx.client("comprehend")
    text = (
        "Bob ordered two sandwiches and three ice cream cones today "
        "from a store in Seattle."
    )

    resp = comprehend.detect_entities(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert len(entities) > 0, "expected at least one entity"

    for entity in entities:
        begin, end = entity["BeginOffset"], entity["EndOffset"]
        assert text[begin:end] == entity["Text"], (
            f"offset [{begin}:{end}] does not slice back to reported text {entity['Text']!r}"
        )

    by_text = {e["Text"]: e["Type"] for e in entities}
    assert by_text.get("Bob") == "PERSON", by_text
    assert by_text.get("Seattle") == "LOCATION", by_text


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
