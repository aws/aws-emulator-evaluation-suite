"""e2e-target-group-deletion-while-referenced-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-target-group-deletion-while-referenced-rejected"
GROUP = "e2e"
SERVICES = ["elbv2"]

_CIDR = "10.95.0.0/16"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a target group a listener's default action references fails with ResourceInUse and
    leaves it describable; after the listener is repointed the same delete succeeds.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    tagspec = lambda kind, name: {  # noqa: E731
        "ResourceType": kind,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{name}-")}],
    }

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=[tagspec("vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose 2 available AZs for ALB subnets")
    subnet_ids = []
    for i, az in enumerate(azs):
        sn = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.95.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[tagspec("subnet", f"subnet-{i}")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sn)
        ctx.on_cleanup(_safe(lambda sid=sn: _delete_net(ec2, "delete_subnet", SubnetId=sid)))

    lb_name = ctx.unique_name("sim2real-inuse-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active", timeout_s=180, interval_s=5,
        description="load balancer reaches active state",
    )

    tg_name = ctx.unique_name("sim2real-inuse-tg-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "Name", "Value": tg_name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _drop_tg(elbv2, lb_arn, tg_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]

    code, message = _error(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    assert code == "ResourceInUse", f"expected ResourceInUse while referenced, got {code!r}"
    expected_in_use = f"Target group '{tg_arn}' is currently in use by a listener or a rule"
    assert message == expected_in_use, f"expected message {expected_in_use!r}, got {message!r}"

    still_there = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"]
    assert still_there and still_there[0]["TargetGroupArn"] == tg_arn, (
        f"target group {tg_arn} must survive the rejected delete; describe returned {still_there!r}"
    )

    elbv2.modify_listener(
        ListenerArn=listener_arn,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
    )

    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    gone_code, gone_message = _error(lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]))
    assert gone_code == "TargetGroupNotFound", (
        f"target group {tg_arn} must be gone once unreferenced and deleted, got {gone_code!r}"
    )
    expected_gone = "One or more target groups not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


_GONE = {"InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "LoadBalancerNotFound",
         "TargetGroupNotFound"}
_BUSY = {"ResourceInUse"}


def _drop_tg(elbv2, lb_arn, tg_arn):
    """Delete the load balancer whose listener references the group first, then the group."""
    _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))()
    _safe(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))()


def _safe(fn, timeout_s=120.0):
    """Teardown: done once the resource is gone; retries while a dependency is still being released."""
    from botocore.exceptions import ClientError

    def _wrapped():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in _GONE:
                    return
                if code not in _BUSY or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _error(fn):
    """Return (code, message) of the AWS error fn raises; raise AssertionError if it succeeds."""
    try:
        result = fn()
    except Exception as err:
        resp = getattr(err, "response", None)
        if resp is None:
            raise
        return resp.get("Error", {}).get("Code"), resp.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
