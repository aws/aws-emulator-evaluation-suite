"""converse-usage-fields."""
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

CHECK = "converse-usage-fields"
GROUP = 'converse'
SERVICES = ['bedrock']

_LONG_PROMPT = (
    "Please repeat the following sentence exactly, word for word, without adding "
    "anything else: The quick brown fox jumps over the lazy dog near the riverbank "
    "at dawn while the town slowly wakes up."
)


def _usage(resp):
    usage = resp["usage"]
    assert "inputTokens" in usage, f"Missing inputTokens. Keys: {list(usage.keys())}"
    assert "outputTokens" in usage, f"Missing outputTokens. Keys: {list(usage.keys())}"
    assert isinstance(usage["inputTokens"], int) and usage["inputTokens"] > 0, (
        f"inputTokens must be a positive int, got {usage['inputTokens']!r}"
    )
    assert isinstance(usage["outputTokens"], int) and usage["outputTokens"] > 0, (
        f"outputTokens must be a positive int, got {usage['outputTokens']!r}"
    )
    return usage


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse usage contains inputTokens and outputTokens, both positive integers,
    and inputTokens grows with prompt length (a stub cannot fake real tokenization)."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    short_usage = _usage(_converse(rt, "Hi.", inference_config={"maxTokens": 1}))
    long_usage = _usage(_converse(rt, _LONG_PROMPT, inference_config={"maxTokens": 1}))
    assert long_usage["inputTokens"] > short_usage["inputTokens"], (
        "a longer prompt must report more inputTokens: "
        f"short={short_usage['inputTokens']} long={long_usage['inputTokens']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
