"""error-model-not-found-converse."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"


class _UnexpectedSuccess(AssertionError):
    """Raised when a call this check requires to be refused instead succeeds."""


def _error(fn):
    """The exact AWS error (code, message), or a loud failure if the call SUCCEEDED.

    Never returns a falsy sentinel on success: an emulator accepting the fake model id must not
    read as an error-code mismatch — it is the strongest possible signal that fidelity is wrong.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise _UnexpectedSuccess(
        f"expected the call to be refused but it returned {result!r}"
    )


def _require_model_access(rt):
    try:
        rt.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "hi"}]}],
            inferenceConfig={"maxTokens": 1},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "") or type(exc).__name__
        raise AssertionError(f"model {MODEL_ID} not usable for inference here ({code})") from exc

CHECK = "error-model-not-found-converse"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse refuses a model id that fails the foundation-model id/ARN pattern.

    The refusal is ValidationException "The provided model identifier is invalid.", after a
    positive-control Converse on a real model succeeds.
    """
    rt = ctx.client("bedrock-runtime")

    # Positive control: the account can converse at all, on the same wiring, before the negative.
    _require_model_access(rt)

    # Break exactly one thing: the model id.
    got = _error(
        lambda: rt.converse(
            modelId="fake.nonexistent-model-v99",
            messages=[{"role": "user", "content": [{"text": "hi"}]}])
    )
    # On AWS this modelId shape (fails the foundation-model id/ARN pattern) is refused with
    # ValidationException; a well-formed but absent ARN (foundation or custom-model) is refused
    # with AccessDeniedException or ValidationException depending on ARN shape, never
    # ResourceNotFoundException.
    expected = ("ValidationException", "The provided model identifier is invalid.")
    assert got == expected, f"Expected {expected!r} for a malformed model id, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
