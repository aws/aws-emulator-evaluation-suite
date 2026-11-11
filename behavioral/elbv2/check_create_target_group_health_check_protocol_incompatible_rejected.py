"""create-target-group-health-check-protocol-incompatible-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-target-group-health-check-protocol-incompatible-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTargetGroup for HTTP with HealthCheckProtocol TCP fails with ValidationError and the exact message
    and creates no target group, while the same settings with an HTTP health check create one."""
    elbv2 = ctx.client("elbv2")
    vpc_id = _ensure_vpc_id(ctx)

    tg_name = _short_name(ctx, "sim2real-tg-hcbad-", 32)

    # --- negative: TCP health checks are unsupported for an HTTP-protocol target
    # group; rejected at CreateTargetGroup time, no target group is created ---
    code, message = _error(
        lambda: elbv2.create_target_group(
            Name=tg_name,
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
            TargetType="instance",
            HealthCheckProtocol="TCP",
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = "Health check protocol 'TCP' must be one of 'HTTP, HTTPS'"
    assert message == expected, f"MSG={message!r}"
    describe_code, describe_message = _error(lambda: elbv2.describe_target_groups(Names=[tg_name]))
    assert describe_code == "TargetGroupNotFound", (
        f"expected TargetGroupNotFound after the rejected create, got {describe_code!r}"
    )
    assert describe_message == "One or more target groups not found", f"MSG={describe_message!r}"

    # --- positive control: the same target group settings, but with a
    # protocol-compatible (HTTP) health check, succeeds ---
    ok_name = _short_name(ctx, "sim2real-tg-hcok-", 32)
    resp = elbv2.create_target_group(
        Name=ok_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        Tags=_tags_kv(),
    )
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    # Independent read at the destination, not the create call's own echo.
    described = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert described["HealthCheckProtocol"] == "HTTP", (
        f"expected the compatible target group to describe as HealthCheckProtocol=HTTP, "
        f"got {described['HealthCheckProtocol']!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    name = ctx.unique_name(prefix)
    return name[:max_len].rstrip("-")


def _tags_kv() -> list:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _ensure_vpc_id(ctx) -> str:
    """Create-or-adopt a VPC to attach the target group to.

    A freshly provisioned account may have no shared network at all, so this never assumes one
    exists: it adopts the shared network when present, and otherwise provisions a small dedicated
    VPC (a target group needs only a VpcId, no subnets or gateway).
    """
    ec2 = ctx.client("ec2")
    # The DescribeVpcs filter is "isDefault" (camelCase) -- there is no "is-default" filter.
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
