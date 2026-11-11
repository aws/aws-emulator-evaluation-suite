"""detect-phi-benign-text-returns-no-entities."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-phi-benign-text-returns-no-entities"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectPHI on text with no personal or health information returns an empty entity list."""
    cm = ctx.client("comprehendmedical")

    # Positive control: same wiring, a text carrying obvious PHI, so a target that
    # answers "no entities" for everything (rather than actually detecting PHI) fails here.
    control_text = "Patient John Smith, DOB 03/14/1958, was seen on 01/05/2023."
    control_resp = cm.detect_phi(Text=control_text)
    control_entities = control_resp["Entities"]
    assert any(
        e["Type"] == "NAME" and "John Smith" in e["Text"] for e in control_entities
    ), f"positive control did not detect the NAME entity, got {control_entities}"

    text = "The weather today is sunny with a light breeze and a gentle north wind."
    resp = cm.detect_phi(Text=text)
    assert resp["Entities"] == [], f"expected no PHI entities, got {resp['Entities']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
