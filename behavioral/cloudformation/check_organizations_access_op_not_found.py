"""organizations-access-op-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "organizations-access-op-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeOrganizationsAccess(CallAs=DELEGATED_ADMIN) from a non-delegated-admin account
    fails with InvalidOperationException "Account used is not a delegated administrator" (or
    OperationNotFoundException) and returns no status, while DescribeAccountLimits succeeds."""
    cfn = ctx.client("cloudformation")

    from botocore.exceptions import ClientError

    # Positive control: an unrelated CloudFormation read must succeed, so the rejection below is
    # the organizations-access boundary, not a credentials or API failure.
    limits = cfn.describe_account_limits().get("AccountLimits")
    assert limits, f"expected a healthy account to report non-empty AccountLimits, got {limits!r}"

    try:
        cfn.describe_organizations_access(CallAs="DELEGATED_ADMIN")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        if code == "InvalidOperationException":
            assert message == "Account used is not a delegated administrator", (
                f"expected a 'not a delegated administrator' message, got {message!r}"
            )
        elif code == "OperationNotFoundException":
            assert "operation" in message.lower(), (
                f"expected an 'operation ... not found' message, got {message!r}"
            )
        else:
            raise AssertionError(
                f"expected OperationNotFoundException or InvalidOperationException, "
                f"got {code} ({message!r})"
            )
        return

    raise AssertionError(
        "account is queryable as a DELEGATED_ADMIN for organizations access without error; "
        "cannot observe the OperationNotFoundException/InvalidOperationException boundary "
        "in this environment"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
