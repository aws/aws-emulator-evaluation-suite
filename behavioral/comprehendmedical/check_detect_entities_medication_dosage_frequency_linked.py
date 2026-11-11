"""detect-entities-medication-dosage-frequency-linked."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-medication-dosage-frequency-linked"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntities links a MEDICATION entity to its DOSAGE and FREQUENCY attributes."""
    cm = ctx.client("comprehendmedical")
    text = "The patient was prescribed 200 mg of ibuprofen twice daily for pain relief."
    resp = cm.detect_entities(Text=text)
    entities = resp["Entities"]

    medication = next(
        (e for e in entities if e["Category"] == "MEDICATION" and "ibuprofen" in e["Text"].lower()),
        None,
    )
    assert medication is not None, f"no MEDICATION entity for ibuprofen found in {entities}"
    assert medication["Type"] in ("GENERIC_NAME", "BRAND_NAME"), (
        f"expected Type in (GENERIC_NAME, BRAND_NAME), got {medication['Type']!r}"
    )

    attr_types = {a["Type"] for a in medication.get("Attributes", [])}
    assert "DOSAGE" in attr_types, f"expected a DOSAGE attribute, got types={attr_types}"
    assert "FREQUENCY" in attr_types, f"expected a FREQUENCY attribute, got types={attr_types}"

    dosage_attr = next(a for a in medication["Attributes"] if a["Type"] == "DOSAGE")
    assert "200" in dosage_attr["Text"], f"expected '200' in DOSAGE attribute Text, got {dosage_attr['Text']!r}"
    frequency_attr = next(a for a in medication["Attributes"] if a["Type"] == "FREQUENCY")
    assert "twice daily" in frequency_attr["Text"].lower(), (
        f"expected 'twice daily' in FREQUENCY attribute Text, got {frequency_attr['Text']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
