"""converse-multiturn-context-retained."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-multiturn-context-retained"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"
SECRET_NUMBER = "7291"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second Converse turn can recall information stated by the user in the first turn."""
    brt = ctx.client("bedrock-runtime")

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "text": (
                        f"My favorite number is {SECRET_NUMBER}. "
                        "Just acknowledge that you noted it in one short sentence."
                    )
                }
            ],
        }
    ]
    first = brt.converse(
        modelId=MODEL_ID, messages=messages, inferenceConfig={"maxTokens": 64, "temperature": 0}
    )
    assert first["stopReason"] == "end_turn", (
        f"expected stopReason end_turn on first turn, got: {first['stopReason']!r}"
    )
    messages.append(first["output"]["message"])
    messages.append(
        {
            "role": "user",
            "content": [{"text": "What is my favorite number? Reply with only the digits."}],
        }
    )

    second = brt.converse(
        modelId=MODEL_ID, messages=messages, inferenceConfig={"maxTokens": 32, "temperature": 0}
    )
    assert second["stopReason"] == "end_turn", (
        f"expected stopReason end_turn on second turn, got: {second['stopReason']!r}"
    )
    text = "".join(b["text"] for b in second["output"]["message"]["content"] if "text" in b)
    assert SECRET_NUMBER in text, f"expected {SECRET_NUMBER} recalled, got: {text!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
