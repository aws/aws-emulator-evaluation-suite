"""list-nodes-reflects-managed-instances."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-nodes-reflects-managed-instances"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceInformation answers, while ListNodes fails with UnsupportedOperationException and the exact
    message when the integrated node experience is not enabled."""
    ssm = ctx.client("ssm")

    control = ssm.describe_instance_information()
    assert "InstanceInformationList" in control, (
        f"DescribeInstanceInformation (positive control) returned no InstanceInformationList: {control}"
    )

    try:
        ssm.list_nodes(MaxResults=50)
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "UnsupportedOperationException", (
            "ListNodes on an account with no Systems Manager integrated experience enabled "
            f"should refuse with UnsupportedOperationException, got {error['Code']!r}: "
            f"{error.get('Message')!r}"
        )
        expected_message = "This is an unsupported operation for this account. You must first enable the Systems Manager integrated experience in your account."
        assert error.get("Message") == expected_message, (
            f"expected the integrated-experience refusal message {expected_message!r}, "
            f"got {error.get('Message')!r}"
        )
        return

    raise AssertionError(
        "ListNodes succeeded on an account with no Systems Manager integrated experience "
        "enabled -- either this sandbox account gained that enrollment (in which case this "
        "check should be rewritten to exercise the real ListNodes-vs-DescribeInstanceInformation "
        "cross-check) or the target is diverging from AWS's documented entitlement gate."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
