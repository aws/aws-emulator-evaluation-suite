"""invoke-model-parameter-out-of-range-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "invoke-model-parameter-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel rejects a temperature value outside the model's documented [0, 1]
    range with ValidationException, instead of clamping it or forwarding it to the
    model unchecked."""
    client = ctx.client("bedrock-runtime")
    model_id = _pick_invokable_model(client)

    code, message = _error(
        lambda: client.invoke_model(
            modelId=model_id, body=_body_for(model_id, 5.0), contentType="application/json"
        )
    )
    assert code == "ValidationException", f"got {code!r}"
    assert message == 'Malformed input request: the provided temperature must be between 0.0 and 1.0, please reformat your input and try again.', f"unexpected refusal message {message!r}"

    # Positive control: an in-range temperature is accepted and produces a real response.
    control = client.invoke_model(
        modelId=model_id, body=_body_for(model_id, 0.5), contentType="application/json"
    )
    payload = json.loads(control["body"].read())
    _assert_real_response(model_id, payload)


_MODEL_CANDIDATES = [
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "amazon.titan-text-express-v1",
]


def _body_for(model_id: str, temperature: float) -> bytes:
    if model_id.startswith("anthropic."):
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 10,
            "temperature": temperature,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        }
    elif model_id.startswith("amazon.nova"):
        payload = {
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 10, "temperature": temperature},
        }
    elif model_id.startswith("amazon.titan"):
        payload = {
            "inputText": "hi",
            "textGenerationConfig": {"maxTokenCount": 10, "temperature": temperature},
        }
    else:
        raise AssertionError(f"no InvokeModel body builder registered for {model_id!r}")
    return json.dumps(payload).encode("utf-8")


def _assert_real_response(model_id: str, payload: dict) -> None:
    if model_id.startswith("anthropic."):
        text = "".join(b["text"] for b in payload["content"] if b.get("type") == "text")
    elif model_id.startswith("amazon.nova"):
        text = "".join(b.get("text", "") for b in payload["output"]["message"]["content"])
    elif model_id.startswith("amazon.titan"):
        text = "".join(r["outputText"] for r in payload["results"])
    else:
        raise AssertionError(f"no response extractor registered for {model_id!r}")
    assert text.strip(), f"expected non-empty generated text for {model_id!r}, got {payload!r}"


def _pick_invokable_model(client) -> str:
    from botocore.exceptions import ClientError

    last_exc = None
    for model_id in _MODEL_CANDIDATES:
        try:
            client.invoke_model(
                modelId=model_id, body=_body_for(model_id, 0.5), contentType="application/json"
            )
            return model_id
        except ClientError as exc:
            last_exc = exc
            continue
    raise AssertionError(
        f"no candidate model is invokable via InvokeModel in this account/region; last error: {last_exc}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

