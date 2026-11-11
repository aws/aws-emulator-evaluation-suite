"""converse-basic-text-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-basic-text-roundtrip"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse returns a well-formed assistant message with consistent token usage."""
    brt = ctx.client("bedrock-runtime")
    resp = brt.converse(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [
                    {"text": "Reply with exactly the single word PONG and nothing else."}
                ],
            }
        ],
        inferenceConfig={"maxTokens": 32, "temperature": 0},
    )

    message = resp["output"]["message"]
    assert message["role"] == "assistant", f"expected role 'assistant', got: {message['role']!r}"
    text_blocks = [b["text"] for b in message["content"] if "text" in b]
    assert text_blocks, "assistant message contained no text content block"
    full_text = "".join(text_blocks)
    assert "pong" in full_text.lower(), f"expected PONG in reply, got: {full_text!r}"

    assert resp["stopReason"] == "end_turn", f"expected stopReason 'end_turn', got: {resp['stopReason']!r}"

    usage = resp["usage"]
    assert usage["inputTokens"] > 0, f"expected positive inputTokens, got: {usage['inputTokens']!r}"
    assert usage["outputTokens"] > 0, f"expected positive outputTokens, got: {usage['outputTokens']!r}"
    assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
        f"expected totalTokens == inputTokens + outputTokens, got: "
        f"{usage['totalTokens']!r} != {usage['inputTokens']!r} + {usage['outputTokens']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
