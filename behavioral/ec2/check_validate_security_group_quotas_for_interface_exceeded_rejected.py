"""validate-security-group-quotas-for-interface-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "validate-security-group-quotas-for-interface-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateSecurityGroupQuotasForInterface is callable only by authorized AWS services: the
    real call fails UnauthorizedOperation, yet DryRun reports DryRunOperation, so the restriction
    sits outside the caller's IAM policy.
    """
    ec2 = ctx.client("ec2")

    vpc_name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.210.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    sg_name = ctx.unique_name("sim2real-behav-sg-")
    group_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral quota check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=group_id))

    # Positive control: the account and credentials are otherwise healthy for EC2.
    described = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    assert described and described[0]["GroupId"] == group_id, (
        f"expected {group_id} in DescribeSecurityGroups results, got {described}"
    )

    # The refusal itself: no caller identity gets past this gate.
    code, message = _refusal(
        lambda: ec2.validate_security_group_quotas_for_interface(SecurityGroupIds=[group_id])
    )
    assert code == "UnauthorizedOperation", f"expected UnauthorizedOperation, got {code}: {message}"
    assert message == "Caller is not allowed to call this API.", f"unexpected message {message!r}"

    # DryRun evaluates only the caller's OWN IAM policy, which this account's does
    # grant -- so it reports the call "would have succeeded". The plain call above is
    # refused anyway: proof the restriction is not a fixable IAM permission gap.
    code, message = _refusal(
        lambda: ec2.validate_security_group_quotas_for_interface(
            SecurityGroupIds=[group_id], DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}: {message}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected message {message!r}"


def _refusal(call) -> tuple[str, str]:
    """Call `call`; return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"ValidateSecurityGroupQuotasForInterface unexpectedly succeeded with "
        f"{result!r}; AWS documents this operation as callable only by AWS services"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
