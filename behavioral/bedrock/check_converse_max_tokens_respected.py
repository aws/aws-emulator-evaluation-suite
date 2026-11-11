"""converse-max-tokens-respected."""
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

CHECK = "converse-max-tokens-respected"
GROUP = 'converse'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with maxTokens=1 stops with 'max_tokens' and outputTokens 1; with maxTokens=512 the
    same prompt does not stop on the cap and yields more output tokens, and on both legs totalTokens is
    inputTokens + outputTokens, so the budget causes the truncation.
    """
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    prompt = "List the integers from 1 to 10, separated by commas. Output nothing else."
    capped = _converse(rt, prompt, inference_config={"maxTokens": 1})
    assert capped["stopReason"] == "max_tokens", (
        f"Expected stopReason='max_tokens' with maxTokens=1, got {capped['stopReason']!r}"
    )
    assert capped["usage"]["outputTokens"] == 1, (
        f"With maxTokens=1, outputTokens must be exactly 1, got {capped['usage']!r}"
    )

    uncapped = _converse(rt, prompt, inference_config={"maxTokens": 512})
    assert uncapped["stopReason"] != "max_tokens", (
        f"With maxTokens=512 the same prompt must not hit the cap again, got "
        f"{uncapped['stopReason']!r} usage={uncapped['usage']!r}"
    )
    assert uncapped["usage"]["outputTokens"] > capped["usage"]["outputTokens"], (
        f"Uncapped generation must produce more output than the capped leg; "
        f"capped={capped['usage']!r} uncapped={uncapped['usage']!r}"
    )

    for label, resp in (("capped", capped), ("uncapped", uncapped)):
        usage = resp["usage"]
        assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
            f"{label} leg: totalTokens must equal inputTokens + outputTokens; usage={usage!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
