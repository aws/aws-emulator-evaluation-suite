"""error-validation-empty-messages."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
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

CHECK = "error-validation-empty-messages"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with empty messages list returns ValidationException."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    code, message = _error(
        lambda: rt.converse(
            modelId=MODEL_ID,
            messages=[])
    )
    assert code == "ValidationException", (
        f"Expected ValidationException for empty messages, got {code!r}"
    )
    expected = (
        "A conversation must start with a user message. "
        "Try again with a conversation that starts with a user message."
    )
    assert message == expected, f"Expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
