"""register-target-type-mismatch-rejected."""
from __future__ import annotations

import ipaddress
import time
from typing import Any

from behavioral_harness import tags

CHECK = "register-target-type-mismatch-rejected"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTargets with an instance id on an ip-type target group fails with ValidationError and the exact
    message and adds nothing, while registering an IP in the group's VPC on the same group succeeds."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    net = _create_network(ctx, ec2)
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-elbv2-tg-")[:32].rstrip("-"),
        Protocol="HTTP",
        Port=80,
        VpcId=net["vpc_id"],
        TargetType="ip",
        Tags=_tags_kv(),
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    bogus_instance_id = "i-0123456789abcdef0"
    code, message = _error(
        lambda: elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": bogus_instance_id}])
    )
    assert code == "ValidationError", f"code={code!r}"
    expected = f"The IP address '{bogus_instance_id}' is not a valid IPv4 address"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    registered_ids = [
        d["Target"]["Id"]
        for d in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    ]
    assert bogus_instance_id not in registered_ids, "the rejected instance-ID target must not have been added"

    # Positive control: a real IP address inside the target group's VPC CIDR succeeds.
    valid_ip = str(ipaddress.ip_address(net["cidr_base"]) + 50)
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": valid_ip, "Port": 80}])
    ctx.on_cleanup(lambda: elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": valid_ip, "Port": 80}]))
    registered_ids_after = [
        d["Target"]["Id"]
        for d in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    ]
    assert valid_ip in registered_ids_after, (
        f"expected {valid_ip!r} in {registered_ids_after!r} after a valid registration on the same target group"
    )


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-elbv2"}]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            return type(exc).__name__, str(exc)
        return response.get("Error", {}).get("Code"), response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_network(ctx, ec2) -> dict[str, Any]:
    """Adopt the run's shared network when one exists; only provision a new VPC as a
    fallback, since CreateTargetGroup(TargetType="ip") needs a VpcId and nothing else
    from the network (no subnets, no load balancer)."""
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc = default_vpcs[0]
        return {"vpc_id": vpc["VpcId"], "cidr_base": vpc["CidrBlock"].split("/")[0]}

    vpc = ec2.create_vpc(
        CidrBlock="10.84.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc["VpcId"])))
    return {"vpc_id": vpc["VpcId"], "cidr_base": "10.84.0.0"}


def _retry_delete(fn, attempts: int = 24, delay: float = 5.0) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("DependencyViolation", "InvalidGroup.InUse", "InvalidVpcID.InUse"):
                last = exc
                time.sleep(delay)
                continue
            raise
    if last:
        raise last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
