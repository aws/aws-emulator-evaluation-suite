"""inference-params-top-p."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

_TOP_P_MESSAGE = (
    "1 validation error detected: Value '1.000001' at 'inferenceConfig.topP' failed to satisfy "
    "constraint: Member must have value less than or equal to 1"
)

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


def _rejection(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected an out-of-range topP to be rejected, but the call succeeded")


CHECK = "inference-params-top-p"
GROUP = 'inference_params'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse accepts an in-range topP and rejects one outside [0, 1]."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = _converse(rt,
        "Say one word.",
        inference_config={"maxTokens": 10, "topP": 0.9})
    assert resp["stopReason"] in ("end_turn", "max_tokens"), f"unexpected stopReason: {resp['stopReason']}"
    assert resp["usage"]["outputTokens"] > 0

    code, message = _rejection(
        lambda: _converse(rt, "Say one word.", inference_config={"maxTokens": 10, "topP": 1.0 + 1e-6})
    )
    assert code == "ValidationException", (
        f"expected ValidationException for topP just above the [0, 1] range, got {code}"
    )
    assert message == _TOP_P_MESSAGE, f"unexpected refusal message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
