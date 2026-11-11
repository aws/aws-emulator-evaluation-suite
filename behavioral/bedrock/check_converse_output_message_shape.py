"""converse-output-message-shape."""
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


def _converse(rt, user_message, *, system=None, inference_config=None):
    kwargs = {"modelId": MODEL_ID, "messages": [{"role": "user", "content": [{"text": user_message}]}]}
    if system:
        kwargs["system"] = [{"text": system}]
    if inference_config:
        kwargs["inferenceConfig"] = inference_config
    return rt.converse(**kwargs)

CHECK = "converse-output-message-shape"
GROUP = 'converse'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse output.message has role='assistant' and content list with text blocks."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = _converse(rt, "Reply with one word.")
    output = resp["output"]
    msg = output.get("message")
    assert msg is not None, f"output.message is None. output keys: {list(output.keys())}"
    assert msg.get("role") == "assistant", f"Expected role='assistant', got {msg.get('role')}"
    content = msg.get("content", [])
    assert isinstance(content, list) and len(content) > 0, "content should be non-empty list"
    text = content[0].get("text")
    assert isinstance(text, str) and len(text) > 0, (
        f"First content block should have a non-empty string 'text'. Got: {content[0]}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
