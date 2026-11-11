"""contains-pii-entities-distinguishes-pii-from-clean-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "contains-pii-entities-distinguishes-pii-from-clean-text"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ContainsPiiEntities flags SSN-bearing text and reports no labels for unrelated clean text."""
    comprehend = ctx.client("comprehend")

    pii_text = "For verification, my social security number is 123-45-6789."
    pii_resp = comprehend.contains_pii_entities(Text=pii_text, LanguageCode="en")
    pii_labels = pii_resp["Labels"]
    assert pii_labels, "expected at least one PII label for SSN-bearing text"
    names = {label["Name"] for label in pii_labels}
    assert "SSN" in names, f"expected SSN label, got {names!r}"
    for label in pii_labels:
        assert 0.0 <= label["Score"] <= 1.0, f"score {label['Score']!r} out of bounds for label {label['Name']!r}"

    clean_text = "The weather today is sunny and warm with a light breeze from the west."
    clean_resp = comprehend.contains_pii_entities(Text=clean_text, LanguageCode="en")
    assert clean_resp["Labels"] == [], f"expected no PII labels for clean text, got {clean_resp['Labels']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
