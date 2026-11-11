"""converse-performance-config-must-not-silently-degrade-to-standard."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "converse-performance-config-must-not-silently-degrade-to-standard"
GROUP = "representation"
SERVICES = ["bedrock-runtime"]

# Pinned: latency-optimised availability is a per-model, per-region fact and is the subject here.
MODEL_ID = "amazon.nova-lite-v1:0"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 64, "temperature": 0.0}
_OPTIMIZED_LATENCY = "optimized"


def _text(resp) -> str:
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """performanceConfig latency "optimized" for a model without support is refused with an exact
    ValidationException rather than served as standard; unset, the member is absent from the reply.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/latency-optimized-inference.html
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    # Positive control. AWS omits performanceConfig from the response when the request did not set
    # it, despite the Smithy default "standard".
    default_resp = rt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    assert default_resp["stopReason"] == "end_turn", (
        f"the control invocation must complete normally, else nothing below can be attributed to "
        f"performanceConfig; got stopReason={default_resp['stopReason']!r} "
        f"text={_text(default_resp)!r}"
    )
    assert "PONG" in _text(default_resp).upper(), (
        f"the control invocation must be a real generation, else this run cannot tell a latency "
        f"routing rule from a broken model; got {_text(default_resp)!r}"
    )
    assert "performanceConfig" not in default_resp, (
        f"real AWS omits the performanceConfig member entirely when the request never set it, "
        f"despite PerformanceConfiguration.latency carrying smithy.api#default=\"standard\"; a "
        f"response that now carries the key is a modelling change this check must be re-recorded "
        f"against, not silently accepted. Got keys {sorted(default_resp)!r}"
    )

    # Ask for the optimised variant and change nothing else.
    refusal = None
    optimized_resp = None
    try:
        optimized_resp = rt.converse(
            modelId=MODEL_ID,
            messages=messages,
            inferenceConfig=_INFERENCE,
            performanceConfig={"latency": _OPTIMIZED_LATENCY},
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        refusal = (err.get("Code", ""), err.get("Message", ""))

    # Real AWS refuses latency optimisation for this model in this region; a 200 for the
    # optimised request (honoured or silently degraded) is not the contract.
    assert refusal is not None, (
        f"real AWS refuses performanceConfig={_OPTIMIZED_LATENCY!r} for {MODEL_ID} in "
        f"{ctx.region}; the call succeeded with "
        f"performanceConfig={optimized_resp.get('performanceConfig')!r} "
        f"stopReason={optimized_resp.get('stopReason')!r}"
    )
    code, message = refusal
    assert code == "ValidationException", (
        f"refusing performanceConfig={_OPTIMIZED_LATENCY!r} must be a specific client error, "
        f"not a server error or a throttle; got {code!r} message={message!r}"
    )
    expected = f"Latency performance configuration is not supported for {MODEL_ID} in {ctx.region}"
    assert message == expected, f"refusal message {message!r}, expected {expected!r}"
    # The identical request without performanceConfig still works and costs the same input tokens.
    again = rt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    assert again["stopReason"] == "end_turn", (
        f"the post-refusal control must complete normally, not degrade into an error or a "
        f"truncation carried over from the refused call; got stopReason={again['stopReason']!r}"
    )
    assert "PONG" in _text(again).upper(), (
        f"the post-refusal control must be a real, independent generation and not a cached or "
        f"degraded echo of the refused call; got {_text(again)!r}"
    )
    assert again["usage"]["inputTokens"] == default_resp["usage"]["inputTokens"], (
        f"after the refusal, the byte-identical control request must still be charged the same "
        f"input tokens, proving the refusal left no residue; first="
        f"{default_resp['usage']!r} after={again['usage']!r}"
    )
    assert "performanceConfig" not in again, (
        f"the post-refusal control must still show the confirmed absent-by-default shape, "
        f"proving the refusal did not leave the account somehow toggled into reporting "
        f"performanceConfig; got keys {sorted(again)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
