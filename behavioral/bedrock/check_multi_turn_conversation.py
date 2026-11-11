"""multi-turn-conversation."""
from __future__ import annotations


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

CHECK = "multi-turn-conversation"
GROUP = 'e2e_workflows'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multi-turn Converse maintains conversational context across turns."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    # First turn: ask the model to remember a word
    resp1 = rt.converse(
        modelId=MODEL_ID,
        messages=[
            {"role": "user", "content": [{"text": "Remember the word: banana"}]},
        ],
        inferenceConfig={"maxTokens": 100})
    assistant_msg = resp1["output"]["message"]
    assert assistant_msg["role"] == "assistant", (
        f"expected first-turn output message role 'assistant', got: {assistant_msg.get('role')!r}"
    )
    # Second turn: ask what word was remembered, passing full history
    resp2 = rt.converse(
        modelId=MODEL_ID,
        messages=[
            {"role": "user", "content": [{"text": "Remember the word: banana"}]},
            assistant_msg,
            {"role": "user", "content": [{"text": "What word did I ask you to remember?"}]},
        ],
        inferenceConfig={"maxTokens": 100})
    output_text = resp2["output"]["message"]["content"][0]["text"].lower()
    assert "banana" in output_text, f"Expected 'banana' in response, got: {output_text!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
