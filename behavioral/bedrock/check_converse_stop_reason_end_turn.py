"""converse-stop-reason-end-turn."""
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

CHECK = "converse-stop-reason-end-turn"
GROUP = 'converse'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A simple prompt yields stopReason='end_turn'."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = _converse(rt, "Say hi.")
    assert resp["stopReason"] == "end_turn", (
        f"Expected stopReason='end_turn', got {resp['stopReason']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
