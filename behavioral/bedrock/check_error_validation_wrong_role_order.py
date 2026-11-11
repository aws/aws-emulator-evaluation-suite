"""error-validation-wrong-role-order."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

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

CHECK = "error-validation-wrong-role-order"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with two consecutive user-role messages is accepted for this model and returns an
    assistant message with content and a stopReason: role alternation is not enforced.
    """
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    try:
        resp = rt.converse(
            modelId=MODEL_ID,
            messages=[
                {"role": "user", "content": [{"text": "first"}]},
                {"role": "user", "content": [{"text": "second"}]},
            ])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            f"Expected consecutive user-role messages to be accepted, got {code!r}"
        ) from exc
    message = resp.get("output", {}).get("message", {})
    assert message.get("role") == "assistant", (
        f"Expected an assistant reply message, got output {message!r}"
    )
    assert message.get("content"), (
        f"Expected non-empty assistant content, got message {message!r}"
    )
    assert resp.get("stopReason"), (
        f"Expected a stopReason on the response, got {resp!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
