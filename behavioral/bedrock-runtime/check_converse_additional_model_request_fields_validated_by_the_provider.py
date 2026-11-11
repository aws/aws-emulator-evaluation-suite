"""converse-additional-model-request-fields-validated-by-the-provider."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "converse-additional-model-request-fields-validated-by-the-provider"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

# additionalModelRequestFields is a smithy Document, so botocore never validates its interior and
# the refusal is server-side.
MODEL_ID = "amazon.nova-lite-v1:0"
_GOOD_TOP_K = 1
_BAD_TOP_K = -1
_FIELD = "topK"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 64, "temperature": 0.0}


def _error(fn):
    """Return (code, message), or RAISE if the call unexpectedly succeeded.

    A falsy sentinel would turn a target that accepted input real AWS rejects into a code mismatch.
    """
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(
        f"an out-of-range {_FIELD}={_BAD_TOP_K} inside additionalModelRequestFields was expected "
        f"to be refused but the call SUCCEEDED, which is an over-permissiveness finding (the "
        f"target is dropping additionalModelRequestFields on the floor instead of forwarding it "
        f"to the provider); response={resp!r}"
    )


def _text(resp) -> str:
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """additionalModelRequestFields reaches the provider: an out-of-range topK is refused with the
    provider's ValidationException, while the same call with a valid topK succeeds before and after.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    def call(top_k):
        return rt.converse(
            modelId=MODEL_ID,
            messages=messages,
            inferenceConfig=_INFERENCE,
            additionalModelRequestFields={"inferenceConfig": {_FIELD: top_k}},
        )

    # Positive control first, so the refusal below is attributable to the field value.
    before = call(_GOOD_TOP_K)
    assert before["stopReason"] == "end_turn", (
        f"the positive control must complete normally with {_FIELD}={_GOOD_TOP_K} in "
        f"additionalModelRequestFields; got stopReason={before['stopReason']!r} "
        f"text={_text(before)!r}"
    )
    assert before["usage"]["outputTokens"] > 0, (
        f"the positive control billed no output tokens, so nothing was generated and the refusal "
        f"below could not be attributed to the field value; usage={before['usage']!r}"
    )
    assert "PONG" in _text(before).upper(), (
        f"the positive control must be a real generation carrying the forced token, else this run "
        f"cannot distinguish a field-validation rule from a broken model; got {_text(before)!r}"
    )

    # Break exactly one scalar inside the pass-through document.
    code, message = _error(lambda: call(_BAD_TOP_K))
    assert code == "ValidationException", (
        f"an out-of-range {_FIELD}={_BAD_TOP_K} inside additionalModelRequestFields must be "
        f"refused with ValidationException by the provider; got {code!r} message={message!r}"
    )
    # The exact message separates "bad value" from "no permissions" or "no such model", which are
    # also 400/403 on this operation.
    assert message == 'The model returned the following errors: Malformed input request: the provided topK must be between 1 and 128, please reformat your input and try again.', (
        f"the refusal must be the provider's parameter-range failure for {_FIELD}; got {message!r}"
    )

    # Restore the scalar; the identical call must succeed again.
    after = call(_GOOD_TOP_K)
    assert after["stopReason"] == "end_turn", (
        f"restoring {_FIELD}={_GOOD_TOP_K} must make the identical call succeed again; got "
        f"stopReason={after['stopReason']!r} text={_text(after)!r}"
    )
    assert "PONG" in _text(after).upper(), (
        f"the restored call must produce a real generation; got {_text(after)!r}"
    )
    # The prompt is byte-identical in both arms, so both must be charged the same input tokens.
    assert after["usage"]["inputTokens"] == before["usage"]["inputTokens"], (
        f"the before and after calls are byte-identical, so they must be charged identical input "
        f"tokens; before={before['usage']!r} after={after['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
