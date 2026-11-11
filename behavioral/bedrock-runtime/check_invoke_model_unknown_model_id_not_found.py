"""invoke-model-unknown-model-id-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "invoke-model-unknown-model-id-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c3", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel and Converse reject a well-formed but nonexistent foundation-model id with
    ValidationException, never success or a 5xx, while a real model still answers."""
    client = ctx.client("bedrock-runtime")
    # A foundation-model ARN: provisioned/custom-model ARNs hit IAM resource-level checks
    # before any existence lookup.
    bogus_model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/anthropic.claude-sim2real-fake-nonexistent-v99:0"

    invoke_code, invoke_message = _error(
        lambda: client.invoke_model(
            modelId=bogus_model_arn,
            body=json.dumps({"inputText": "hello"}).encode("utf-8"),
            contentType="application/json",
        )
    )
    assert invoke_code == "ValidationException", f"expected ValidationException, got code={invoke_code}"
    assert invoke_message == 'The provided model identifier is invalid.', f"unexpected refusal message {invoke_message!r}"
    assert invoke_code not in ("InternalServerException",), (
        f"InvokeModel against an unknown modelId must not collapse into a 5xx, got {invoke_code}"
    )

    converse_code, converse_message = _error(
        lambda: client.converse(
            modelId=bogus_model_arn,
            messages=[{"role": "user", "content": [{"text": "hello"}]}],
        )
    )
    assert converse_code == "ValidationException", f"expected ValidationException, got code={converse_code}"
    assert converse_message == 'The provided model identifier is invalid.', f"unexpected refusal message {converse_message!r}"
    assert converse_code not in ("InternalServerException",), (
        f"Converse against an unknown modelId must not collapse into a 5xx, got {converse_code}"
    )

    # Positive control: a real model returns generated text, not just an empty envelope.
    real_model_id = _pick_converse_model(client)
    real_resp = client.converse(
        modelId=real_model_id,
        messages=[{"role": "user", "content": [{"text": "Say the word 'pong' and nothing else."}]}],
    )
    content_blocks = real_resp["output"]["message"]["content"]
    assert any(block.get("text", "").strip() for block in content_blocks), (
        f"positive control must produce actual generated text, got content={content_blocks!r}"
    )
    assert real_resp["usage"]["outputTokens"] > 0, (
        f"positive control must report real inference usage, got usage={real_resp.get('usage')!r}"
    )




_CONVERSE_MODEL_CANDIDATES = [
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "amazon.titan-text-express-v1",
]


def _pick_converse_model(client):
    from botocore.exceptions import ClientError

    last_exc = None
    for model_id in _CONVERSE_MODEL_CANDIDATES:
        try:
            client.converse(
                modelId=model_id,
                messages=[{"role": "user", "content": [{"text": "ping"}]}],
                inferenceConfig={"maxTokens": 5},
            )
            return model_id
        except ClientError as exc:
            last_exc = exc
            continue
    raise AssertionError(
        f"no candidate Converse model is invokable in this account/region; last error: {last_exc}"
    )


def _error(fn):
    """Return fn()'s ClientError (code, message), draining any stream; raise on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
        if isinstance(result, dict) and "stream" in result:
            for _ in result["stream"]:
                pass
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
