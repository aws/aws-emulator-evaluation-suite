"""converse-malformed-message-structure-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-malformed-message-structure-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with a message whose content list is empty is refused with ValidationException and
    the exact empty-content message, while the same call with a text block returns generated text.
    """
    client = ctx.client("bedrock-runtime")
    model_id = _pick_converse_model(client)

    code, message = _error(
        lambda: client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": []}],
        )
    )
    assert code == "ValidationException", f"got {code!r}"
    assert message == 'The content field in the Message object at messages.0 is empty. Add a ContentBlock object to the content field and try again.', f"unexpected refusal message {message!r}"

    # Positive control: the same call with a non-empty content block succeeds and
    # produces real generated text, not merely a well-formed empty envelope.
    control = client.converse(
        modelId=model_id,
        messages=[{"role": "user", "content": [{"text": "Say the word 'pong' and nothing else."}]}],
    )
    control_content = control["output"]["message"]["content"]
    assert any("text" in block and block["text"].strip() for block in control_content), control_content


_CONVERSE_MODEL_CANDIDATES = [
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
    "amazon.titan-text-express-v1",
]


def _pick_converse_model(client):
    from botocore.exceptions import ClientError

    last_exc = None
    for candidate in _CONVERSE_MODEL_CANDIDATES:
        try:
            client.converse(
                modelId=candidate,
                messages=[{"role": "user", "content": [{"text": "ping"}]}],
                inferenceConfig={"maxTokens": 5},
            )
            return candidate
        except ClientError as exc:
            last_exc = exc
            continue
    raise AssertionError(
        f"no candidate Converse model is invokable in this account/region; last error: {last_exc}"
    )


def _error(fn):
    """Return (code, message) of the ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected Converse to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
