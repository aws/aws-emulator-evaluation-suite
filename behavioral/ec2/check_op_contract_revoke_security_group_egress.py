"""op-contract-revoke-security-group-egress."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-revoke-security-group-egress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeSecurityGroupEgress removes an authorized egress rule, as seen via
    DescribeSecurityGroups; revoking it again, or revoking a never-authorized rule, is rejected
    with InvalidPermission.NotFound."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real behavioral test sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    rule = {
        "IpProtocol": "tcp",
        "FromPort": 8443,
        "ToPort": 8443,
        "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
    }
    never_authorized_rule = {
        "IpProtocol": "tcp",
        "FromPort": 8444,
        "ToPort": 8444,
        "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
    }

    def _has_rule(port: int) -> bool:
        perms = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0][
            "IpPermissionsEgress"
        ]
        return any(
            p.get("FromPort") == port
            and any(r.get("CidrIp") == "203.0.113.0/24" for r in p.get("IpRanges", []))
            for p in perms
        )

    ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=[rule])
    assert _has_rule(8443), "authorize_security_group_egress did not add the expected rule"

    ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[rule])
    assert not _has_rule(8443), "revoke_security_group_egress did not remove the rule"

    code = _error_code(
        lambda: ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[rule])
    )
    assert code == "InvalidPermission.NotFound", f"unexpected error code re-revoking: {code}"

    code = _error_code(
        lambda: ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[never_authorized_rule])
    )
    assert code == "InvalidPermission.NotFound", (
        f"unexpected error code revoking a never-authorized rule: {code}"
    )


def _error_code(fn):
    """Return the error code of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
