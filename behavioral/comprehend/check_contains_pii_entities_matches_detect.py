"""contains-pii-entities-matches-detect."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "contains-pii-entities-matches-detect"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ContainsPiiEntities's label summary agrees with the entity types that
    DetectPiiEntities finds in the same document."""
    comprehend = ctx.client("comprehend")
    text = "Please contact John at john.doe@example.com for the invoice."

    contains_resp = comprehend.contains_pii_entities(Text=text, LanguageCode="en")
    detect_resp = comprehend.detect_pii_entities(Text=text, LanguageCode="en")

    contains_labels = {label["Name"] for label in contains_resp["Labels"]}
    detected_types = {entity["Type"] for entity in detect_resp["Entities"]}

    assert "EMAIL" in contains_labels, f"expected EMAIL label, got {contains_labels}"
    assert "EMAIL" in detected_types, f"expected EMAIL entity type, got {detected_types}"
    # ContainsPiiEntities' coarse label set and DetectPiiEntities' entity type set
    # describe the same document, so they must agree exactly -- a label with no
    # corroborating entity, or an entity type missing from the label summary, is
    # a disagreement either way.
    assert contains_labels == detected_types, (
        f"ContainsPiiEntities labels {contains_labels} disagree with "
        f"DetectPiiEntities types {detected_types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
