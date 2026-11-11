"""converse-stop-sequence-halts-generation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-stop-sequence-halts-generation"
GROUP = "state"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Nova Converse call asked to count to 100 with stop sequence '7' ends with stopReason
    end_turn and text ending at '7', never reaching 100: the stop sequence cuts generation short.
    """
    brt = ctx.client("bedrock-runtime")
    resp = brt.converse(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "text": (
                            "Output exactly the following, separated by single spaces and "
                            "nothing else, no punctuation, no preamble: count from 1 to 100"
                        )
                    }
                ],
            }
        ],
        inferenceConfig={"maxTokens": 400, "temperature": 0, "stopSequences": ["7"]},
    )
    assert resp["stopReason"] == "end_turn", f"stopReason={resp['stopReason']!r} text={resp['output']['message']['content']!r}"
    text = "".join(b["text"] for b in resp["output"]["message"]["content"] if "text" in b)
    # A model asked to count to 100 that stops at "7" was clearly cut off mid-task, not
    # naturally concluding -- proving the halt is driven by the stop sequence.
    assert "100" not in text, f"generation should have halted long before 100, got: {text!r}"
    assert text.strip().endswith("7"), f"expected generation to end right at the stop sequence, got: {text!r}"
    assert "1" in text, f"expected the pre-stop-sequence text to be present, got: {text!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
