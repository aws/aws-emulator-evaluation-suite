"""invoke-model-with-response-stream-nova-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "invoke-model-with-response-stream-nova-roundtrip"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModelWithResponseStream on Nova opens with messageStart, its text deltas reassemble
    into text containing PONG, and the stream ends with stopReason end_turn or max_tokens and a
    metadata usage event with a positive token count.
    """
    brt = ctx.client("bedrock-runtime")
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [{"text": "Reply with exactly the word PONG and nothing else."}],
                }
            ],
            "inferenceConfig": {"temperature": 0, "topP": 1.0, "maxTokens": 20},
        }
    )
    resp = brt.invoke_model_with_response_stream(
        modelId=MODEL_ID, body=body, contentType="application/json", accept="application/json"
    )

    text_chunks = []
    stop_reason = None
    usage = None
    saw_message_start = False
    for event in resp["body"]:
        chunk = json.loads(event["chunk"]["bytes"])
        if "messageStart" in chunk:
            saw_message_start = True
        delta = chunk.get("contentBlockDelta", {}).get("delta", {})
        if "text" in delta:
            text_chunks.append(delta["text"])
        if "messageStop" in chunk:
            stop_reason = chunk["messageStop"]["stopReason"]
        if "metadata" in chunk and "usage" in chunk["metadata"]:
            usage = chunk["metadata"]["usage"]

    full_text = "".join(text_chunks)
    assert saw_message_start, "expected a messageStart event to open the stream"
    assert "pong" in full_text.lower(), f"expected PONG in reassembled stream text, got: {full_text!r}"
    assert stop_reason in ("end_turn", "max_tokens"), stop_reason
    assert usage, "expected a metadata event carrying a usage object"
    token_fields = {k: v for k, v in usage.items() if "oken" in k}
    assert token_fields and any(v > 0 for v in token_fields.values()), usage


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

