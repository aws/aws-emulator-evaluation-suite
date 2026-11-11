"""infer-rxnorm-returns-metformin-concept."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "infer-rxnorm-returns-metformin-concept"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InferRxNorm links a metformin mention to an RxNorm concept describing metformin."""
    cm = ctx.client("comprehendmedical")
    text = "Patient is taking metformin 500 mg twice daily."
    resp = cm.infer_rx_norm(Text=text)
    entities = resp["Entities"]

    med_entity = next((e for e in entities if "metformin" in e["Text"].lower()), None)
    assert med_entity is not None, f"no metformin entity found in {entities}"
    assert med_entity["Category"] == "MEDICATION", f"expected Category MEDICATION, got {med_entity}"
    assert med_entity["Type"] in ("GENERIC_NAME", "BRAND_NAME"), f"expected Type GENERIC_NAME/BRAND_NAME, got {med_entity}"

    concepts = med_entity["RxNormConcepts"]
    assert concepts, f"expected at least one RxNorm concept for {med_entity}"
    descriptions = [c["Description"].lower() for c in concepts]
    assert any("metformin" in d for d in descriptions), f"expected metformin in {descriptions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
