"""delete-remediation-exceptions-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-remediation-exceptions-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRemediationExceptions for a rule and resource with no remediation exception fails with
    NoSuchRemediationExceptionException "Specified RemediationException could not be found.", while
    DescribeRemediationExceptions for that rule fails with InvalidParameterValueException and its message."""
    config = ctx.client("config")

    rule_name = ctx.unique_name("sim2real-remexc-rule-")
    resource_key = {"ResourceType": "AWS::EC2::Instance", "ResourceId": ctx.unique_name("sim2real-remexc-res-")}

    code, message = _error_code(
        lambda: config.delete_remediation_exceptions(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
    )
    assert code == "NoSuchRemediationExceptionException", f"expected NoSuchRemediationExceptionException, got {code!r}"
    assert message == "Specified RemediationException could not be found.", f"unexpected message: {message!r}"

    # Terminal read, at a different operation than the mutating delete: the read path
    # independently confirms the rule has no remediation configuration to hold exceptions,
    # rejecting the never-existed rule name with InvalidParameterValueException.
    after_code, after_message = _error_code(
        lambda: config.describe_remediation_exceptions(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
    )
    assert after_code == "InvalidParameterValueException", f"unexpected code: {after_code!r}"
    assert after_message == "No Remediation Configuration found for exception", (
        f"unexpected message: {after_message!r}"
    )


def _error_code(fn):
    """Return (code, message) of the rejection; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
