"""converse-basic-response-shape."""
from __future__ import annotations

import time

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

CHECK = "converse-basic-response-shape"
GROUP = 'converse'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse returns output, stopReason, usage, metrics — with correctly-typed contents, not just present keys."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    start = time.monotonic()
    resp = _converse(rt, "Say hello.")
    elapsed_ms = (time.monotonic() - start) * 1000

    assert "output" in resp, f"Missing 'output'. Keys: {list(resp.keys())}"
    msg = resp["output"].get("message")
    assert msg is not None and msg.get("role") == "assistant", (
        f"output.message should have role='assistant', got {msg!r}"
    )
    content = msg.get("content") or []
    assert isinstance(content, list) and content and content[0].get("text"), (
        f"output.message.content should be a non-empty list of text blocks, got {content!r}"
    )

    assert "stopReason" in resp and isinstance(resp["stopReason"], str) and resp["stopReason"], (
        f"stopReason should be a non-empty string. Keys: {list(resp.keys())}"
    )

    assert "usage" in resp, f"Missing 'usage'. Keys: {list(resp.keys())}"
    usage = resp["usage"]
    in_tokens, out_tokens = usage.get("inputTokens"), usage.get("outputTokens")
    assert isinstance(in_tokens, int) and in_tokens > 0, f"usage.inputTokens should be a positive int, got {in_tokens!r}"
    assert isinstance(out_tokens, int) and out_tokens > 0, f"usage.outputTokens should be a positive int, got {out_tokens!r}"
    assert usage.get("totalTokens") == in_tokens + out_tokens, (
        f"usage.totalTokens ({usage.get('totalTokens')!r}) should equal "
        f"inputTokens+outputTokens ({in_tokens + out_tokens})"
    )

    assert "metrics" in resp, f"Missing 'metrics'. Keys: {list(resp.keys())}"
    latency_ms = resp["metrics"].get("latencyMs")
    assert isinstance(latency_ms, (int, float)) and 0 < latency_ms <= elapsed_ms + 5000, (
        f"metrics.latencyMs ({latency_ms!r}) should be positive and within our own "
        f"measured wall-clock time for the call ({elapsed_ms:.0f}ms + margin)"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
