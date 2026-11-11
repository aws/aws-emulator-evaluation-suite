"""converse-system-prompt."""
from __future__ import annotations

import uuid

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


def _converse(rt, user_message, *, system=None):
    kwargs = {"modelId": MODEL_ID, "messages": [{"role": "user", "content": [{"text": user_message}]}]}
    if system:
        kwargs["system"] = [{"text": system}]
    return rt.converse(**kwargs)


def _text(resp):
    msg = resp["output"]["message"]
    assert msg["role"] == "assistant", f"expected assistant role, got {msg['role']!r}"
    assert len(msg["content"]) > 0, "assistant message has no content blocks"
    return msg["content"][0].get("text", "")

CHECK = "converse-system-prompt"
GROUP = 'converse'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A system prompt naming a one-off marker actually shapes the answer; the same question with no system prompt does not produce it."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)

    marker = f"SP-MARKER-{uuid.uuid4().hex[:12]}"
    user_message = "What are you? Answer in one short sentence."

    baseline_text = _text(_converse(rt, user_message))
    assert marker not in baseline_text, (
        f"marker {marker} unexpectedly present with no system prompt: {baseline_text!r}"
    )

    guided_text = _text(_converse(
        rt,
        user_message,
        system=(
            f"You must begin your reply with the exact literal token {marker}, "
            "then continue answering normally."
        ),
    ))
    assert marker in guided_text, (
        f"system prompt did not influence the response: expected marker {marker} in {guided_text!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
