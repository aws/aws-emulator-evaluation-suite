"""inference-params-temperature."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

_PROMPT = "In one creative sentence, describe an imaginary alien city."
_TRIALS = 5


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


def _sample(rt, temperature):
    resp = _converse(
        rt,
        _PROMPT,
        inference_config={"maxTokens": 40, "temperature": temperature},
    )
    assert resp["stopReason"] in ("end_turn", "max_tokens"), (
        f"temperature={temperature} call returned stopReason={resp['stopReason']!r}"
    )
    assert resp["usage"]["outputTokens"] > 0, (
        f"temperature={temperature} call produced zero output tokens"
    )
    text = "".join(b.get("text", "") for b in resp["output"]["message"]["content"])
    return text

CHECK = "inference-params-temperature"
GROUP = 'inference_params'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Repeated Converse calls on the same prompt give strictly more distinct outputs at
    temperature=1.0 than at temperature=0.0: temperature is honored (temperature=0.0 is not fully
    deterministic on Bedrock, so the claim is the comparison, not identical cold outputs).
    """
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)

    cold_outputs = [_sample(rt, 0.0) for _ in range(_TRIALS)]
    hot_outputs = [_sample(rt, 1.0) for _ in range(_TRIALS)]
    cold_distinct = len(set(cold_outputs))
    hot_distinct = len(set(hot_outputs))
    assert hot_distinct > cold_distinct, (
        f"temperature=1.0 on the identical prompt should diverge MORE than temperature=0.0 did, "
        f"but temperature=1.0 gave {hot_distinct} distinct outputs across {_TRIALS} calls versus "
        f"{cold_distinct} distinct at temperature=0.0 -- temperature appears to have no effect on "
        f"generation. cold={cold_outputs!r} hot={hot_outputs!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
