"""detect-entities-empty-text-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-entities-empty-text-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError for empty Text, call succeeded: {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntitiesV2 with an empty Text (validation off in the client, so the service judges it) fails
    with ValidationException and its exact message, while a non-empty Text returns Entities."""
    cm = ctx.client("comprehendmedical")

    # Positive control: non-empty text on the same operation succeeds.
    resp = cm.detect_entities_v2(Text="Patient takes 10 mg of lisinopril daily.")
    assert "Entities" in resp, f"expected an Entities key on a valid call, got {resp.keys()}"

    raw = ctx.client("comprehendmedical", config=Config(parameter_validation=False))
    code, message = _error(lambda: raw.detect_entities_v2(Text=""))
    assert code == "ValidationException", f"expected ValidationException for empty Text, got {code}"
    expected = (
        "1 validation error detected: Value at 'text' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Same call through the raw (unvalidated) client still succeeds when Text is non-empty.
    control_raw = raw.detect_entities_v2(Text="Patient takes 10 mg of lisinopril daily.")
    assert "Entities" in control_raw, f"expected an Entities key on a valid call, got {control_raw.keys()}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
