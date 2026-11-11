"""op-contract-revoke-security-group-ingress."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-revoke-security-group-ingress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeSecurityGroupIngress removes a previously authorized ingress rule (verified via
    DescribeSecurityGroups), and revoking a rule that was never authorized on that group is
    rejected with InvalidPermission.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.89.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real behavioral test sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    rule = {
        "IpProtocol": "tcp",
        "FromPort": 2222,
        "ToPort": 2222,
        "IpRanges": [{"CidrIp": "198.51.100.0/24"}],
    }
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[rule])

    def _has_rule() -> bool:
        perms = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0][
            "IpPermissions"
        ]
        return any(
            p.get("FromPort") == 2222
            and any(r.get("CidrIp") == "198.51.100.0/24" for r in p.get("IpRanges", []))
            for p in perms
        )

    assert _has_rule(), "authorize_security_group_ingress did not add the expected rule"

    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[rule])
    assert not _has_rule(), "revoke_security_group_ingress did not remove the rule"

    code, message = _error(
        lambda: ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[rule])
    )
    assert code == "InvalidPermission.NotFound", f"unexpected error code: {code}"
    assert message == "The specified rule does not exist in this security group.", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
