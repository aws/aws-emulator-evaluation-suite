"""op-contract-revoke-security-group-ingress-wrong-group-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-revoke-security-group-ingress-wrong-group-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Revoking group A's ingress rule via same-VPC group B is rejected with
    InvalidPermission.NotFound and leaves the rule on A; the same revoke on A succeeds."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_a = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-a-"),
        Description="sim2real behavioral test sg A",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_a))

    sg_b = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-b-"),
        Description="sim2real behavioral test sg B",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_b))

    rule = {
        "IpProtocol": "tcp",
        "FromPort": 9000,
        "ToPort": 9000,
        "IpRanges": [{"CidrIp": "192.0.2.0/24"}],
    }
    ec2.authorize_security_group_ingress(GroupId=sg_a, IpPermissions=[rule])
    ctx.on_cleanup(lambda: _revoke_quiet(ec2, sg_a, rule))

    def _has_rule(group_id: str) -> bool:
        perms = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0][
            "IpPermissions"
        ]
        return any(
            p.get("FromPort") == 9000
            and any(r.get("CidrIp") == "192.0.2.0/24" for r in p.get("IpRanges", []))
            for p in perms
        )

    err = _error(
        lambda: ec2.revoke_security_group_ingress(GroupId=sg_b, IpPermissions=[rule])
    )
    assert err["Code"] == "InvalidPermission.NotFound", f"unexpected error: {err!r}"
    assert err.get("Message") == "The specified rule does not exist in this security group.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    assert _has_rule(
        sg_a
    ), "rule on sg_a was affected by the rejected cross-group revoke on sg_b"

    # Positive control: without it, an implementation that always rejects the revoke would
    # pass the cross-group rejection above.
    ec2.revoke_security_group_ingress(GroupId=sg_a, IpPermissions=[rule])
    assert not _has_rule(
        sg_a
    ), "revoke_security_group_ingress did not remove the rule from its own group"


def _revoke_quiet(ec2, group_id, rule):
    """Cleanup: revoke the rule, tolerating one the check already revoked."""
    from botocore.exceptions import ClientError

    try:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[rule])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPermission.NotFound":
            raise


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
