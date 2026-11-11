"""detect-phi-detects-name-age-and-date."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-phi-detects-name-age-and-date"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectPHI recognizes a person's NAME, AGE and DATE as PROTECTED_HEALTH_INFORMATION."""
    cm = ctx.client("comprehendmedical")
    text = "Patient John Smith is a 45 year old male, seen on 04/12/2023."
    resp = cm.detect_phi(Text=text)
    entities = resp["Entities"]

    assert all(e["Category"] == "PROTECTED_HEALTH_INFORMATION" for e in entities), entities

    name_entity = next((e for e in entities if e["Type"] == "NAME"), None)
    assert name_entity is not None, f"no NAME entity found in {entities}"
    assert "John Smith" in name_entity["Text"], (
        f"expected NAME entity text to contain 'John Smith', got {name_entity['Text']!r}"
    )

    age_entity = next((e for e in entities if e["Type"] == "AGE"), None)
    assert age_entity is not None, f"no AGE entity found in {entities}"
    assert "45" in age_entity["Text"], (
        f"expected AGE entity text to contain '45', got {age_entity['Text']!r}"
    )

    date_entity = next((e for e in entities if e["Type"] == "DATE"), None)
    assert date_entity is not None, f"no DATE entity found in {entities}"
    assert "04/12/2023" in date_entity["Text"], (
        f"expected DATE entity text to contain '04/12/2023', got {date_entity['Text']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
