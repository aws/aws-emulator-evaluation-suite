"""create-provisioned-throughput-zero-units-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-provisioned-throughput-zero-units-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProvisionedModelThroughput with modelUnits=0 returns the exact modelUnits
    ValidationException, modelUnits=1 on the same model the exact no-commitment
    ServiceQuotaExceededException, and neither call provisions anything under its name.
    """
    bedrock = ctx.client("bedrock")
    eligible = bedrock.list_foundation_models(byInferenceType="PROVISIONED")[
        "modelSummaries"
    ]
    assert eligible, "account reports no PROVISIONED-inference-eligible foundation model"
    model_id = eligible[0]["modelArn"]
    model_short_id = eligible[0]["modelId"]
    name = ctx.unique_name("sim2real-pt-zero-")

    # botocore's own shape validator would reject modelUnits=0 locally (it never
    # leaves the process) because the service's min-value constraint is baked into
    # the generated model; disable client-side param validation so the request
    # actually reaches the service and we observe *its* rejection.
    raw_bedrock = ctx.client("bedrock", config=Config(parameter_validation=False))

    got = _error_code(
        lambda: raw_bedrock.create_provisioned_model_throughput(
            modelUnits=0, provisionedModelName=name, modelId=model_id
        )
    )
    expected = (
        "ValidationException",
        "1 validation error detected: Value at 'modelUnits' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # effect absent: no provisioned throughput was created under that name
    listing = bedrock.list_provisioned_model_throughputs()
    matches = [
        p
        for p in listing.get("provisionedModelSummaries", [])
        if p.get("provisionedModelName") == name
    ]
    assert matches == [], f"expected no match for {name!r}, found {matches!r}"

    # distinguishing control: an otherwise-valid request on the SAME model is refused
    # too, but for the account's quota state, not for the request's shape.
    pos_name = ctx.unique_name("sim2real-pt-ok-")
    pos_got = _error_code(
        lambda: bedrock.create_provisioned_model_throughput(
            modelUnits=1,
            provisionedModelName=pos_name,
            modelId=model_id,
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    )
    pos_expected = (
        "ServiceQuotaExceededException",
        f"Your account does not currently have any no commitment model units reserved for "
        f"{model_short_id}. Please see https://support.console.aws.amazon.com/support/home"
        f"?region={ctx.region}#/case/create?issueType=service-limit-increase to request a "
        f"service quota increase.",
    )
    assert pos_got == pos_expected, f"expected {pos_expected!r}, got {pos_got!r}"

    # effect absent for the control too: nothing was provisioned under either name
    listing2 = bedrock.list_provisioned_model_throughputs()
    matches2 = [
        p
        for p in listing2.get("provisionedModelSummaries", [])
        if p.get("provisionedModelName") in (name, pos_name)
    ]
    assert matches2 == [], f"expected no match for {name!r}/{pos_name!r}, found {matches2!r}"


def _error_code(fn):
    """Return the (code, message) fn raises; a success raises. A ParamValidationError
    propagates, as it means the request never left the SDK."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

