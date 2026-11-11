"""list-managed-insight-rules-missing-required-param."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-managed-insight-rules-missing-required-param"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListManagedInsightRules sent without ResourceARN raises MissingParameter, and with a string that
    does not parse as an ARN raises InvalidParameterValue, each with its exact message; a well-formed
    ARN of an unsupported resource type returns an empty ManagedRules list."""
    cw = ctx.client("cloudwatch")
    novalidate_cw = ctx.client("cloudwatch", config=Config(parameter_validation=False))

    # Positive control: the account and credentials are otherwise healthy for this
    # operation, so neither negative below can be "everything is rejected" in disguise.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    well_formed_arn = f"arn:aws:sqs:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-behav-cw-')}"
    control = cw.list_managed_insight_rules(ResourceARN=well_formed_arn)
    assert control["ManagedRules"] == [], control["ManagedRules"]

    code_missing, message_missing = _error(lambda: novalidate_cw.list_managed_insight_rules())
    assert code_missing == "MissingParameter", f"expected MissingParameter, got {code_missing!r}"
    assert message_missing == 'MISSING_RESOURCE_ARN: The ResourceARN parameter must be present.', f"unexpected MissingParameter message: {message_missing!r}"

    malformed_resource_arn = f"not-a-valid-arn-{ctx.unique_name('sim2real-behav-cw-')}"
    code_invalid, message_invalid = _error(
        lambda: novalidate_cw.list_managed_insight_rules(ResourceARN=malformed_resource_arn)
    )
    assert code_invalid == "InvalidParameterValue", (
        f"expected an InvalidParameterValue-family error for a malformed ARN, got {code_invalid!r}"
    )
    assert message_invalid == 'INVALID_RESOURCE_ARN: Invalid ARN.', f"unexpected message for a malformed ARN: {message_invalid!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
