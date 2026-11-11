"""target-group-deregistration-delay-attribute-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-group-deregistration-delay-attribute-round-trip"
GROUP = "control-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTargetGroupAttributes persists deregistration_delay.timeout_seconds and the default
    value (300) is present before any modification."""
    vpc_id = _own_vpc(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, vpc_id)
    arn = tg["TargetGroupArn"]

    initial = {a["Key"]: a["Value"] for a in elbv2.describe_target_group_attributes(TargetGroupArn=arn)["Attributes"]}
    assert initial.get("deregistration_delay.timeout_seconds") == "300", initial

    elbv2.modify_target_group_attributes(
        TargetGroupArn=arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "45"}],
    )

    updated = {a["Key"]: a["Value"] for a in elbv2.describe_target_group_attributes(TargetGroupArn=arn)["Attributes"]}
    assert updated["deregistration_delay.timeout_seconds"] == "45", updated


# ===== helpers =====
def _safe(fn):
    """Teardown delete: an already-gone resource is clean; every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "TargetGroupNotFound"):
            raise


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _own_vpc(ctx):
    # Prefer an existing shared network -- cheap, and does not draw on the account's VPC
    # quota. Only create one if none exists, so a freshly provisioned account (no default
    # VPC) still works without ever depending on one being there.
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        return default_vpcs[0]["VpcId"]
    vpc_id = ec2.create_vpc(CidrBlock="10.178.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
    )
    return vpc_id


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip", "Tags": _tags_kv()}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
    return tg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
