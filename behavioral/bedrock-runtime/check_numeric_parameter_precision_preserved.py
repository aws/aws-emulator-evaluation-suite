"""numeric-parameter-precision-preserved."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "numeric-parameter-precision-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"


def _error_code(fn):
    """Return (code, message) of the refusal; RAISE if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _converse(ctx, temperature: float, top_p: float):
    # botocore's local ParamValidator only ever enforces a shape's `min` (see
    # botocore/validate.py:range_check, which has no `max` branch at all), so
    # temperature=1.0+1e-6 (over max) already reaches the service, but
    # topP=-1e-6 (under min) would be rejected inside the SDK and never leave the
    # process. Disabling client-side validation forces both edge values onto the
    # wire so the assertions below observe the SERVICE's own boundary check.
    bedrock = ctx.client("bedrock-runtime", config=Config(parameter_validation=False))
    return bedrock.converse(
        modelId=TEXT_MODEL,
        messages=[{"role": "user", "content": [{"text": "Say hello."}]}],
        inferenceConfig={"temperature": temperature, "topP": top_p, "maxTokens": 10},
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse accepts temperature=1.0 with topP=0.0 but refuses temperature=1.0+1e-6 and
    topP=-1e-6 with ValidationException and the exact range messages: the bounds are checked at full
    precision.
    """
    # Exact boundary values are accepted (positive control).
    ok_resp = _converse(ctx, temperature=1.0, top_p=0.0)
    assert ok_resp["output"]["message"]["content"][0]["text"].strip() != ""

    # A temperature a hair above the max is rejected -- proving the server compares against the
    # full-precision submitted float rather than a rounded approximation of it.
    def _over_temp():
        return _converse(ctx, temperature=1.0 + 1e-6, top_p=0.0)

    over_temp_code, over_temp_message = _error_code(_over_temp)
    assert over_temp_code == "ValidationException", f"expected ValidationException, got {over_temp_code}"
    assert over_temp_message == (
        "1 validation error detected: Value '1.000001' at 'inferenceConfig.temperature' failed to "
        "satisfy constraint: Member must have value less than or equal to 1"
    ), over_temp_message

    # A topP a hair below the min is likewise rejected at full precision.
    def _under_top_p():
        return _converse(ctx, temperature=0.0, top_p=-1e-6)

    under_top_p_code, under_top_p_message = _error_code(_under_top_p)
    assert under_top_p_code == "ValidationException", f"expected ValidationException, got {under_top_p_code}"
    assert under_top_p_message == (
        "1 validation error detected: Value '-1.0E-6' at 'inferenceConfig.topP' failed to "
        "satisfy constraint: Member must have value greater than or equal to 0"
    ), under_top_p_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
