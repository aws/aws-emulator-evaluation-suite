"""bedrock-runtime-bare-model-id-needing-inference-profile-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-bare-model-id-needing-inference-profile-rejected"
GROUP = 'overly-permissive'
SERVICES = ['bedrock-runtime']

# PROFILE_ONLY_MODEL is refused by its bare id and accepted through INFERENCE_PROFILE_ID;
# ON_DEMAND_MODEL is accepted by its bare id. If AWS makes the first on-demand invocable,
# this check fails first and names the reason.
PROFILE_ONLY_MODEL = "amazon.nova-micro-v1:0"
INFERENCE_PROFILE_ID = "us.amazon.nova-micro-v1:0"
ON_DEMAND_MODEL = "amazon.nova-lite-v1:0"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 64, "temperature": 0.0}


def _error_code(fn):
    """Return the AWS error (code, message), or raise if the call unexpectedly succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code", ""),
                exc.response.get("Error", {}).get("Message", ""))
    raise AssertionError(
        f"the call was expected to be refused but SUCCEEDED, which is an over-permissiveness "
        f"finding, not a code mismatch; response={resp!r}"
    )


def _text(resp):
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A model reachable only through a cross-region inference profile refuses its bare model id
    with ValidationException, while its profile id and another on-demand model's bare id work.
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    # Run first: proves the model is invocable, so the refusal below is a routing rule, not an
    # unavailable model.
    via_profile = rt.converse(modelId=INFERENCE_PROFILE_ID, messages=messages,
                              inferenceConfig=_INFERENCE)
    assert via_profile["stopReason"] == "end_turn", (
        f"the inference-profile invocation must complete normally; got "
        f"{via_profile['stopReason']!r} text={_text(via_profile)!r}"
    )
    assert "PONG" in _text(via_profile).upper(), (
        f"the inference-profile invocation must be a real generation carrying the forced token; "
        f"got {_text(via_profile)!r}"
    )
    assert via_profile["usage"]["outputTokens"] > 0, (
        f"the inference-profile invocation billed no output tokens, so nothing was generated; "
        f"usage={via_profile['usage']!r}"
    )

    # The same request, naming the same model by its bare id.
    code, message = _error_code(
        lambda: rt.converse(modelId=PROFILE_ONLY_MODEL, messages=messages,
                            inferenceConfig=_INFERENCE)
    )
    assert code == "ValidationException", (
        f"a bare model id for a model that is only reachable through a cross-region inference "
        f"profile must be refused with ValidationException; got {code!r} message={message!r}. "
        f"If AWS has made {PROFILE_ONLY_MODEL} on-demand invocable, this check is the intended "
        f"tripwire: update the PROFILE_ONLY_MODEL / INFERENCE_PROFILE_ID pair rather than "
        f"weakening the assertion."
    )
    assert message == "Invocation of model ID amazon.nova-micro-v1:0 with on-demand throughput isn\u2019t supported. Retry your request with the ID or ARN of an inference profile that contains this model.", (
        f"the refusal must name the inference-profile remedy for the model it refused, rather "
        f"than being a generic validation failure; got {message!r}"
    )

    # A different on-demand model still works by its bare id, so the refusal is per-model.
    on_demand = rt.converse(modelId=ON_DEMAND_MODEL, messages=messages,
                            inferenceConfig=_INFERENCE)
    assert on_demand["stopReason"] == "end_turn", (
        f"the on-demand control must complete normally, else the refusal above may be a blanket "
        f"outage; got {on_demand['stopReason']!r} text={_text(on_demand)!r}"
    )
    assert "PONG" in _text(on_demand).upper(), (
        f"the on-demand control produced no usable generation, so this run cannot distinguish a "
        f"per-model routing rule from an account-wide problem; got {_text(on_demand)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
