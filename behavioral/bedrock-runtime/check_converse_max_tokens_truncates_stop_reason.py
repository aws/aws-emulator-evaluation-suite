"""converse-max-tokens-truncates-stop-reason."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-max-tokens-truncates-stop-reason"
GROUP = "state"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A tiny maxTokens budget forces stopReason=max_tokens and caps usage.outputTokens."""
    brt = ctx.client("bedrock-runtime")
    resp = brt.converse(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [{"text": "Write a detailed 500 word essay about the history of Rome."}],
            }
        ],
        inferenceConfig={"maxTokens": 5, "temperature": 0},
    )
    assert resp["stopReason"] == "max_tokens", resp["stopReason"]
    assert resp["usage"]["outputTokens"] <= 5, resp["usage"]["outputTokens"]
    text = "".join(b["text"] for b in resp["output"]["message"]["content"] if "text" in b)
    assert text.strip(), "truncated response should still contain some generated text"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
