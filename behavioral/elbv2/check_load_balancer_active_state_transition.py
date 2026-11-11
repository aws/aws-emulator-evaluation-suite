"""load-balancer-active-state-transition."""
from __future__ import annotations

import socket
import time

from behavioral_harness import tags

CHECK = "load-balancer-active-state-transition"
GROUP = "state"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created ALB settles in active with a resolvable DNS name."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=net["subnet_ids"],
        Type="application",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "Name", "Value": name}],
    )
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))

    assert lb["State"]["Code"], f"expected CreateLoadBalancer to report a state, got {lb}"
    assert lb["Type"] == "application", f"expected type application, got {lb['Type']!r}"

    final_state = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code in ("active", "active_impaired", "failed"),
        timeout_s=180,
        interval_s=5,
    )
    assert final_state == "active", f"load balancer never reached active state: {final_state}"

    described = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert described["DNSName"], "active load balancer must expose a DNS name"
    assert described["State"]["Code"] == "active", f"expected active, got {described['State']}"

    resolved_ip = _poll_until(
        lambda: _try_resolve(ctx, described["DNSName"]),
        lambda ip: ip is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert resolved_ip, f"DNS name {described['DNSName']!r} never resolved to an address"


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


def _safe(fn) -> None:
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s, anything else raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _try_resolve(ctx, hostname):
    """The address ``hostname`` resolves to at the routed endpoint, or None while it does not."""
    try:
        return socket.gethostbyname(ctx.endpoint_host(hostname, 80)[0])
    except socket.gaierror:
        return None


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
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
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
    return _create_vpc_and_subnets(ctx, ec2)


def _create_vpc_and_subnets(ctx, ec2):
    vpc_id = ec2.create_vpc(CidrBlock="10.66.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")},
    ])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    subnet_cidrs = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        cidr = f"10.66.{i}.0/24"
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
        ec2.create_tags(Resources=[subnet_id], Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-subnet-")},
        ])
        subnet_ids.append(subnet_id)
        subnet_cidrs.append(cidr)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "subnet_cidrs": subnet_cidrs}


# Resources in this VPC (load balancers, endpoints, functions, ...) delete asynchronously and
# leave ENIs behind, so network deletes answer DependencyViolation for a while. Wait, bounded,
# for those ENIs to go, then raise naming any still attached. The window is shared by all of a
# check's network deletes.
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
