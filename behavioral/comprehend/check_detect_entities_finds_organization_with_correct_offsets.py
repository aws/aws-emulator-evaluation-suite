"""detect-entities-finds-organization-with-correct-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-finds-organization-with-correct-offsets"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntities finds a known ORGANIZATION entity whose offsets exactly bound the source substring."""
    comprehend = ctx.client("comprehend")
    text = "Amazon Web Services was founded in Seattle and is led by Andy Jassy."
    resp = comprehend.detect_entities(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert entities, "expected at least one detected entity"

    for entity in entities:
        begin, end = entity["BeginOffset"], entity["EndOffset"]
        assert text[begin:end] == entity["Text"], (
            f"entity offsets [{begin}:{end}] -> {text[begin:end]!r} do not match reported Text {entity['Text']!r}"
        )

    orgs = [e for e in entities if e["Type"] == "ORGANIZATION"]
    assert orgs, f"expected an ORGANIZATION entity, got types {[e['Type'] for e in entities]!r}"

    org = orgs[0]
    substring = text[org["BeginOffset"]:org["EndOffset"]]
    assert "Amazon" in substring, f"expected the ORGANIZATION substring to mention Amazon, got {substring!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
