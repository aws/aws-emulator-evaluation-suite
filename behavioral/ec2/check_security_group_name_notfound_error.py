"""security-group-name-notfound-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-name-notfound-error"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSecurityGroups for a nonexistent group name fails with InvalidGroup.NotFound and a message
    naming the group in the default VPC; a name, unlike an id, has no format to fail first."""
    ec2 = ctx.client("ec2")
    missing_name = ctx.unique_name("sim2real-behav-absent-sg-")
    try:
        ec2.describe_security_groups(GroupNames=[missing_name])
        code, message = None, None
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    assert code == "InvalidGroup.NotFound", f"expected InvalidGroup.NotFound, got {code}"
    # AWS names the account's default VPC at the end of the message; that id varies per account.
    expected_prefix = f"The security group '{missing_name}' does not exist in default VPC 'vpc-"
    assert message is not None and message.startswith(expected_prefix) and message.endswith("'"), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
