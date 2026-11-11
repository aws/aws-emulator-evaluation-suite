"""infer-rxnorm-text-exceeds-ontology-size-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "infer-rxnorm-text-exceeds-ontology-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected TextSizeLimitExceededException, but the call SUCCEEDED and returned {str(result)[:200]}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InferRxNorm rejects Text longer than the documented 10000-character ontology-linking limit."""
    cm = ctx.client("comprehendmedical")
    oversized_text = "Patient takes metformin 500 mg twice daily. " * 300  # well over 10000 chars
    assert len(oversized_text) > 10000, f"test bug: oversized_text only {len(oversized_text)} chars"

    code, message = _error(lambda: cm.infer_rx_norm(Text=oversized_text))
    assert code == "TextSizeLimitExceededException", f"expected TextSizeLimitExceededException, got {code}"
    expected = (
        "1 validation error detected: Value at 'text' failed to satisfy constraint: "
        "Member must have length less than or equal to 10000"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: text under the limit on the same operation still succeeds, and actually
    # links the medication mention to an RxNorm concept (not just "the call returned 200").
    resp = cm.infer_rx_norm(Text="Patient takes metformin 500 mg twice daily.")
    entities = resp["Entities"]
    med_entity = next((e for e in entities if "metformin" in e["Text"].lower()), None)
    assert med_entity is not None, f"no metformin entity found in {entities}"
    assert med_entity["Category"] == "MEDICATION", f"expected Category MEDICATION, got {med_entity}"
    concepts = med_entity["RxNormConcepts"]
    assert concepts, f"expected at least one RxNorm concept for {med_entity}"
    descriptions = [c["Description"].lower() for c in concepts]
    assert any("metformin" in d for d in descriptions), f"expected metformin in {descriptions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
