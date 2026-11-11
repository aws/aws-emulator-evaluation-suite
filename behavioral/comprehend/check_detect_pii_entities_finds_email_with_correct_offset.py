"""detect-pii-entities-finds-email-with-correct-offset."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-pii-entities-finds-email-with-correct-offset"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectPiiEntities locates an email address in free text and reports an EMAIL entity
    whose BeginOffset/EndOffset slice back to exactly that email address."""
    comprehend = ctx.client("comprehend")
    email = "jane.doe@example.com"
    text = f"You can reach Jane at {email} for further details."

    resp = comprehend.detect_pii_entities(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert len(entities) > 0, "expected at least one PII entity"

    email_entities = [e for e in entities if e["Type"] == "EMAIL"]
    assert len(email_entities) == 1, (
        f"expected exactly one EMAIL entity, got types {[e['Type'] for e in entities]!r}"
    )
    found = email_entities[0]
    begin, end = found["BeginOffset"], found["EndOffset"]
    assert text[begin:end] == email, f"offset [{begin}:{end}] -> {text[begin:end]!r} != {email!r}"
    score = found["Score"]
    assert 0.0 <= score <= 1.0, f"expected Score in [0.0, 1.0], got {score!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
