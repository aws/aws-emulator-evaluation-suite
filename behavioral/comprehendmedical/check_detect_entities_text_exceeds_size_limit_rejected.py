"""detect-entities-text-exceeds-size-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-entities-text-exceeds-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises, so a
    target that accepts oversized text fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected TextSizeLimitExceededException, but the call succeeded: {str(result)[:200]}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntitiesV2 rejects Text longer than the documented 20000-character limit."""
    cm = ctx.client("comprehendmedical")
    base = "The patient has a mild headache. "
    repeats = (20000 // len(base)) + 10
    oversized_text = base * repeats
    assert len(oversized_text) > 20000, f"test bug: oversized_text only {len(oversized_text)} chars"

    code, message = _error(lambda: cm.detect_entities_v2(Text=oversized_text))
    assert code == "TextSizeLimitExceededException", f"expected TextSizeLimitExceededException, got {code}"
    expected = (
        "1 validation error detected: Value at 'text' failed to satisfy constraint: "
        "Member must have length less than or equal to 20000"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: text under the limit on the same operation still succeeds.
    resp = cm.detect_entities_v2(Text="The patient has a mild headache.")
    assert "Entities" in resp, f"expected an Entities key in the positive-control response, got keys {list(resp.keys())}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
