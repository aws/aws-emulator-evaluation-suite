"""converse-nonexistent-model-resource-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "converse-nonexistent-model-resource-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

REAL_MODEL_ID = "amazon.nova-lite-v1:0"
FAKE_MODEL_ID = "amazon.sim2real-does-not-exist-v1"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with a well-formed but nonexistent modelId is refused with ValidationException ('The
    provided model identifier is invalid.'), while the same call on a real model completes.
    """
    brt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": "Say hello."}]}]

    code, message = _error(
        lambda: brt.converse(modelId=FAKE_MODEL_ID, messages=messages, inferenceConfig={"maxTokens": 8})
    )
    assert code == "ValidationException", code
    assert message == 'The provided model identifier is invalid.', f"unexpected refusal message {message!r}"

    control = brt.converse(modelId=REAL_MODEL_ID, messages=messages, inferenceConfig={"maxTokens": 8})
    assert control["stopReason"] in ("end_turn", "max_tokens"), (
        f"positive control against a real model must complete normally; got {control['stopReason']!r}"
    )


def _error(fn):
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call against a nonexistent modelId was expected to be refused but SUCCEEDED, "
        f"which is an over-permissiveness finding, not a code mismatch; response={resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
