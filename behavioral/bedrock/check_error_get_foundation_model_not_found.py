"""error-get-foundation-model-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"


def _error(fn):
    """Call fn() and return its Error dict; a success raises, as the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


CHECK = "error-get-foundation-model-not-found"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFoundationModel on an unrecognized model identifier returns ValidationException 'The
    provided model identifier is invalid.' (not a not-found error), while a known model ID returns
    its modelDetails."""
    bc = ctx.client("bedrock")

    control = bc.get_foundation_model(modelIdentifier=MODEL_ID)
    assert control.get("modelDetails", {}).get("modelId") == MODEL_ID, (
        f"positive control failed: expected modelId={MODEL_ID}, "
        f"got {control.get('modelDetails', {}).get('modelId')!r}"
    )

    error = _error(
        lambda: bc.get_foundation_model(modelIdentifier="fake.nonexistent-xyz-v1")
    )
    got = (error.get("Code"), error.get("Message", ""))
    expected = ("ValidationException", "The provided model identifier is invalid.")
    assert got == expected, (
        f"Expected {expected!r} for an unrecognized model identifier, got {got!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
