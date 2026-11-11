"""register-targets-exceeding-max-batch-size-rejected."""
from __future__ import annotations

import ipaddress

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-targets-exceeding-max-batch-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTargets with 1,001 targets (over the 1,000-per-target-group quota) fails with
    TooManyTargets and registers none of them; a 5-target batch on the same group succeeds."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet = _network_subnet(ctx)
    tg_arn = _create_target_group(ctx, vpc_id)

    oversized_batch = [{"Id": ip} for ip in _synthetic_ips(subnet, 1001)]
    code, message = _error_code(
        lambda: elbv2.register_targets(TargetGroupArn=tg_arn, Targets=oversized_batch)
    )
    assert code == "TooManyTargets", f"expected TooManyTargets, got {code!r}"
    assert message == f"The maximum number of targets on target group '{tg_arn}' has been reached", (
        message
    )

    registered = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert registered == [], f"expected no registered targets, got {registered!r}"

    small_batch = [{"Id": ip} for ip in _synthetic_ips(subnet, 5)]
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=small_batch)
    registered_after = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert len(registered_after) == 5, f"expected 5 registered targets, got {len(registered_after)}: {registered_after!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


_MIN_SUBNET_ADDRESSES = 4096  # a /20 or larger: room for 1,001 + 5 synthetic targets plus AWS's
# 5 reserved addresses per subnet, with margin.


def _network_subnet(ctx) -> tuple[str, ipaddress.IPv4Network]:
    """Return (vpc_id, cidr) of a shared-network subnet large enough for the synthetic targets.
    An ip target must fall inside a subnet of the target group's VPC, not just the VPC CIDR."""
    ec2 = ctx.client("ec2")
    for subnet in ec2.describe_subnets(SubnetIds=ctx.network().subnet_ids)["Subnets"]:
        net = ipaddress.ip_network(subnet["CidrBlock"])
        if net.num_addresses >= _MIN_SUBNET_ADDRESSES:
            return subnet["VpcId"], net
    raise AssertionError(
        f"no subnet of the run's shared network has {_MIN_SUBNET_ADDRESSES} addresses"
    )


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol="TCP", Port=80, VpcId=vpc_id, TargetType="ip"
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _synthetic_ips(subnet: ipaddress.IPv4Network, count: int) -> list[str]:
    """Addresses in the subnet, skipping AWS's reserved first four and last addresses.
    `hosts()` already drops network and broadcast, so three more are skipped."""
    usable = list(subnet.hosts())[3:]
    if len(usable) < count:
        raise RuntimeError(
            f"subnet {subnet} has only {len(usable)} usable addresses, need {count}"
        )
    return [str(ip) for ip in usable[:count]]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


