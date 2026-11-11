"""contains-pii-entities-flags-multiple-categories."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "contains-pii-entities-flags-multiple-categories"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ContainsPiiEntities reports every distinct PII category present in the text (not just the
    first one found) when the text contains both an SSN and an email address."""
    comprehend = ctx.client("comprehend")
    text = (
        "My social security number is 123-45-6789 and you can email me at "
        "test@example.com for more information."
    )

    resp = comprehend.contains_pii_entities(Text=text, LanguageCode="en")
    labels = resp["Labels"]
    assert len(labels) > 0, "expected at least one PII label"

    names = {label["Name"] for label in labels}
    assert "SSN" in names, f"expected SSN in labels, got {names}"
    assert "EMAIL" in names, f"expected EMAIL in labels, got {names}"
    for label in labels:
        assert 0.0 <= label["Score"] <= 1.0, f"score out of [0,1] bounds: {label}"

    ssn_label = next(label for label in labels if label["Name"] == "SSN")
    email_label = next(label for label in labels if label["Name"] == "EMAIL")
    assert ssn_label["Score"] > 0.5, f"expected high-confidence SSN score, got {ssn_label}"
    assert email_label["Score"] > 0.5, f"expected high-confidence EMAIL score, got {email_label}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
