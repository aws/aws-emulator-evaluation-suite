"""infer-snomedct-returns-concepts-and-character-count."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "infer-snomedct-returns-concepts-and-character-count"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InferSNOMEDCT links a condition to a SNOMED-CT concept and reports the input character count."""
    cm = ctx.client("comprehendmedical")
    text = "Patient was diagnosed with pneumonia."
    resp = cm.infer_snomedct(Text=text)
    entities = resp["Entities"]

    characters = resp["Characters"]["OriginalTextCharacters"]
    assert characters == len(text), f"expected OriginalTextCharacters {len(text)}, got {characters}"
    language = resp["SNOMEDCTDetails"]["Language"]
    assert language == "en", f"expected SNOMEDCTDetails.Language 'en', got {language!r}"

    condition_entity = next(
        (e for e in entities if e["Category"] == "MEDICAL_CONDITION" and "pneumonia" in e["Text"].lower()),
        None,
    )
    assert condition_entity is not None, f"no pneumonia MEDICAL_CONDITION entity found in {entities}"

    concepts = condition_entity["SNOMEDCTConcepts"]
    assert concepts, f"expected at least one SNOMED-CT concept for {condition_entity}"
    descriptions = [c["Description"].lower() for c in concepts]
    assert any("pneumonia" in d for d in descriptions), f"expected pneumonia in {descriptions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
