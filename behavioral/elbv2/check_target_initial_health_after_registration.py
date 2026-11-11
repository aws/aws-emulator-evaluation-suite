"""target-initial-health-after-registration."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-initial-health-after-registration"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTargets makes a new ip target immediately visible with health state 'initial'."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, net["vpc_id"])
    # A target group's targets only get health-checked (and therefore show 'initial') once the
    # target group is actually associated with a load balancer via a listener. An unassociated
    # target group reports its targets as 'unused' (reason Target.NotInUse) immediately, since no
    # health checks are ever performed against it.
    lb = _create_alb(ctx, net["subnet_ids"])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )
    # Give the target group <-> load balancer association itself a moment to propagate before
    # registering the target, otherwise the target can still land in 'unused' transiently.
    _poll_until(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[tg["TargetGroupArn"]])["TargetGroups"][0].get(
            "LoadBalancerArns", []
        ),
        lambda arns: lb["LoadBalancerArn"] in arns,
        timeout_s=30,
        interval_s=2,
    )
    target_ip = _pick_ip(net["subnet_cidrs"][0], offset=15)

    elbv2.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": target_ip, "Port": 80}])
    ctx.on_cleanup(
        lambda: _safe(
            lambda: elbv2.deregister_targets(
                TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": target_ip, "Port": 80}]
            )
        )
    )

    health = elbv2.describe_target_health(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": target_ip, "Port": 80}]
    )["TargetHealthDescriptions"]
    assert len(health) == 1, f"expected exactly one target health entry, got {health!r}"
    entry = health[0]
    assert entry["Target"]["Id"] == target_ip, f"expected target id {target_ip!r}, got {entry['Target']['Id']!r}"
    assert entry["Target"]["Port"] == 80, f"expected target port 80, got {entry['Target']['Port']!r}"
    # Right after registration, and before any health check round completes, AWS reports 'initial'.
    assert entry["TargetHealth"]["State"] == "initial", entry["TargetHealth"]

    # The target must also show up in the unfiltered listing for the target group.
    all_health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    ids = [d["Target"]["Id"] for d in all_health]
    assert target_ip in ids, f"registered target {target_ip} missing from unfiltered describe_target_health: {ids}"


# ===== helpers =====
_GONE_CODES = (
    "LoadBalancerNotFound", "TargetGroupNotFound", "InvalidTarget",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
)


def _safe(fn):
    """Teardown call: an already-gone resource is clean; every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_vpc_and_subnets(ctx):
    # A freshly provisioned account may have no shared network; fall back to a
    # self-created VPC + subnets rather than depending on one being ambient.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s)
        if len(by_az) >= 2:
            chosen = list(by_az.values())[:2]
            return {
                "vpc_id": vpc_id,
                "subnet_ids": [s["SubnetId"] for s in chosen],
                "subnet_cidrs": [s["CidrBlock"] for s in chosen],
            }
    return _create_vpc_and_subnets(ctx)


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": "behavioral"}])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids, subnet_cidrs = [], []
    for i in range(2):
        cidr = f"10.99.{i}.0/24"
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=azs[i % len(azs)]["ZoneName"]
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "sim2real", "Value": "behavioral"}])
        subnet_ids.append(subnet_id)
        subnet_cidrs.append(cidr)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "subnet_cidrs": subnet_cidrs}


def _pick_ip(cidr, offset=10):
    net = ipaddress.ip_network(cidr)
    return str(net.network_address + offset)


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {
        "Name": name,
        "Protocol": "HTTP",
        "Port": 80,
        "VpcId": vpc_id,
        "TargetType": "ip",
        "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_target_group_when_free(elbv2, arn)))
    return tg


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _wait_for_lb_active(ctx, arn, timeout_s=180, interval_s=5):
    elbv2 = ctx.client("elbv2")
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


# A load balancer in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries that code in one shared window, then raises naming the ENIs.
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



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
