"""infer-icd10cm-returns-diabetes-code."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "infer-icd10cm-returns-diabetes-code"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InferICD10CM links a diabetes diagnosis to an ICD-10-CM code in the E11.x range."""
    cm = ctx.client("comprehendmedical")
    text = "Patient has a history of type 2 diabetes mellitus."
    resp = cm.infer_icd10_cm(Text=text)
    entities = resp["Entities"]

    diabetes_entity = next(
        (e for e in entities if e["Category"] == "MEDICAL_CONDITION" and "diabetes" in e["Text"].lower()),
        None,
    )
    assert diabetes_entity is not None, f"no diabetes MEDICAL_CONDITION entity found in {entities}"
    assert diabetes_entity["Type"] == "DX_NAME", f"expected Type DX_NAME, got {diabetes_entity['Type']!r}"

    begin, end = diabetes_entity["BeginOffset"], diabetes_entity["EndOffset"]
    assert text[begin:end] == diabetes_entity["Text"], (
        f"offsets [{begin}:{end}] into {text!r} give {text[begin:end]!r}, not entity Text {diabetes_entity['Text']!r}"
    )

    concepts = diabetes_entity["ICD10CMConcepts"]
    assert concepts, f"expected at least one ICD10CM concept for {diabetes_entity}"
    codes = [c["Code"] for c in concepts]
    assert any(code.startswith("E11") for code in codes), f"expected an E11.x code, got {codes}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
