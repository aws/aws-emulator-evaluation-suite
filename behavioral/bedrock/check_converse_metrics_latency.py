"""converse-metrics-latency."""
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

CHECK = "converse-metrics-latency"
GROUP = 'converse'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse metrics carries latencyMs as a positive number no larger than the
    client-measured wall clock of the same call plus 500 ms."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    start = time.monotonic()
    resp = _converse(rt, "Hi.")
    wall_ms = (time.monotonic() - start) * 1000
    metrics = resp["metrics"]
    assert "latencyMs" in metrics, f"Missing latencyMs. Keys: {list(metrics.keys())}"
    latency_ms = metrics["latencyMs"]
    assert latency_ms > 0, f"latencyMs should be positive, got {latency_ms}"
    assert latency_ms <= wall_ms + 500, (
        f"latencyMs ({latency_ms}) exceeds the client-measured wall clock "
        f"({wall_ms:.1f}ms) by more than network slack allows"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
