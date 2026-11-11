"""modify-listener-attributes-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "modify-listener-attributes-round-trip"
GROUP = "control-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyListenerAttributes persists a routing.http.response header attribute, an
    independent DescribeListenerAttributes reflects the new value, and reverting the same
    attribute is reflected again — a genuine round trip rather than a one-way default flip."""
    net = _vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    tg = _create_target_group(ctx, net["vpc_id"])

    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    attr_key = "routing.http.response.server.enabled"

    before = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_listener_attributes(ListenerArn=listener_arn)["Attributes"]
    }
    assert attr_key in before, (
        f"DescribeListenerAttributes on a fresh listener omitted {attr_key!r}: {sorted(before)!r}"
    )
    original = before[attr_key]
    assert original in ("true", "false"), f"{attr_key}={original!r} is not a boolean string"
    flipped = "false" if original == "true" else "true"

    elbv2.modify_listener_attributes(
        ListenerArn=listener_arn,
        Attributes=[{"Key": attr_key, "Value": flipped}],
    )
    after_flip = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_listener_attributes(ListenerArn=listener_arn)["Attributes"]
    }
    assert after_flip.get(attr_key) == flipped, (
        f"expected {attr_key}={flipped!r} after modify, got {after_flip.get(attr_key)!r}"
    )

    elbv2.modify_listener_attributes(
        ListenerArn=listener_arn,
        Attributes=[{"Key": attr_key, "Value": original}],
    )
    after_restore = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_listener_attributes(ListenerArn=listener_arn)["Attributes"]
    }
    assert after_restore.get(attr_key) == original, (
        f"expected {attr_key}={original!r} after restoring, got {after_restore.get(attr_key)!r}"
    )


# ===== helpers =====
# Not-found codes a teardown treats as already deleted; an in-use target group is retried.
_GONE = frozenset({
    "ListenerNotFound", "RuleNotFound", "TargetGroupNotFound", "LoadBalancerNotFound",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
})


def _safe(fn):
    """Run one teardown call: a resource already gone is fine; one still held by a deleting load
    balancer (ResourceInUse) is retried every 2 s for up to 180 s; any other error raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _vpc_and_subnets(ctx):
    """Reuse a VPC that already spans >=2 AZs when one exists, else provision one. Avoids
    depending on an ambient default VPC, which a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    reused = _find_reusable_vpc(ec2, ctx=ctx)
    if reused:
        return reused

    name = ctx.unique_name("sim2real-elbv2-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    if len(azs) < 2:
        raise AssertionError(f"region exposes only {len(azs)} available AZs, need 2")
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_name = ctx.unique_name("sim2real-elbv2-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.95.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _find_reusable_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    vpcs = sorted(vpcs, key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) < 2:
            continue
        return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())[:2]}
    return None


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Tags=[{"Key": "Name", "Value": name}],
    )
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {
        "Name": name,
        "Protocol": "HTTP",
        "Port": 80,
        "VpcId": vpc_id,
        "TargetType": "ip",
        "Tags": [{"Key": "Name", "Value": name}],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
    return tg


# A load balancer or instance in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation.
# Teardown waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the
# check's network deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
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
