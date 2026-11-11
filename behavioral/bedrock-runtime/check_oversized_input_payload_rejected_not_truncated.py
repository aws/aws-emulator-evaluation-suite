"""oversized-input-payload-rejected-not-truncated."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oversized-input-payload-rejected-not-truncated"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"
# Nova Lite has a 300K-token context window; this is far beyond any model's window and does not
# depend on knowing the exact limit.
_HUGE_TEXT = "lorem ipsum dolor sit amet " * 150000
_TOKENS_EXCEEDED_MESSAGE = (
    "Input Tokens Exceeded: Number of input tokens exceeds maximum length. "
    "Please update the input to try again."
)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the oversized call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _nova_body(text: str) -> bytes:
    return json.dumps(
        {"messages": [{"role": "user", "content": [{"text": text}]}], "inferenceConfig": {"maxTokens": 20, "temperature": 0, "topP": 1}}
    ).encode("utf-8")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel and Converse each refuse an oversized prompt with ValidationException and the
    exact token-limit message instead of truncating it, while a small prompt returns text on both.
    """
    bedrock = ctx.client("bedrock-runtime")

    # Positive control (InvokeModel): small input succeeds and produces real output.
    small_resp = bedrock.invoke_model(
        modelId=TEXT_MODEL, body=_nova_body("Say hello."), contentType="application/json"
    )
    small_body = json.loads(small_resp["body"].read())
    small_text = small_body["output"]["message"]["content"][0]["text"].strip()
    assert small_text != "", f"expected non-empty InvokeModel output, got {small_text!r}"

    # Oversized input via InvokeModel is rejected outright, not truncated-and-processed.
    def _oversized_invoke_model():
        bedrock.invoke_model(
            modelId=TEXT_MODEL, body=_nova_body(_HUGE_TEXT), contentType="application/json"
        )

    code, message = _error_code(_oversized_invoke_model)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == _TOKENS_EXCEEDED_MESSAGE, message

    # Positive control (Converse): small input succeeds with a normal end_turn completion.
    small_conv = bedrock.converse(
        modelId=TEXT_MODEL, messages=[{"role": "user", "content": [{"text": "Say hello."}]}]
    )
    assert small_conv["stopReason"] == "end_turn", f"expected end_turn, got {small_conv['stopReason']!r}"
    small_conv_text = small_conv["output"]["message"]["content"][0]["text"].strip()
    assert small_conv_text != "", f"expected non-empty Converse output, got {small_conv_text!r}"

    # Oversized input via Converse is rejected outright with a ValidationException -- never
    # silently truncated into a partial completion.
    def _oversized_converse():
        bedrock.converse(
            modelId=TEXT_MODEL, messages=[{"role": "user", "content": [{"text": _HUGE_TEXT}]}]
        )

    converse_code, converse_message = _error_code(_oversized_converse)
    assert converse_code == "ValidationException", f"expected ValidationException, got {converse_code}"
    assert converse_message == (
        "The model returned the following errors: " + _TOKENS_EXCEEDED_MESSAGE
    ), converse_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
