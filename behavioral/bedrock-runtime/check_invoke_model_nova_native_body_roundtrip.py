"""invoke-model-nova-native-body-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "invoke-model-nova-native-body-roundtrip"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel with a native Nova request body (messages/inferenceConfig) returns a
    native Nova response body (output.message.content / stopReason / usage), not an
    InvokeModel-shaped legacy Titan payload."""
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
    resp = brt.invoke_model(modelId=MODEL_ID, body=body, contentType="application/json", accept="application/json")
    assert resp["contentType"] == "application/json", f"expected application/json, got {resp['contentType']!r}"

    payload = json.loads(resp["body"].read())
    assert payload["usage"]["inputTokens"] > 0, f"expected positive inputTokens, got {payload['usage']}"
    content = payload["output"]["message"]["content"]
    text_blocks = [b["text"] for b in content if "text" in b]
    assert text_blocks, content
    assert "pong" in text_blocks[0].lower(), text_blocks[0]
    assert payload["stopReason"] in ("end_turn", "max_tokens"), f"unexpected stopReason: {payload['stopReason']!r}"
    assert payload["usage"]["outputTokens"] > 0, f"expected positive outputTokens, got {payload['usage']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
