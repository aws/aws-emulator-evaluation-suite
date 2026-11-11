"""set-ip-address-type-unsupported-for-load-balancer-type-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "set-ip-address-type-unsupported-for-load-balancer-type-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """dualstack-without-public-ipv4 is ALB-only: an NLB rejects it with InvalidConfigurationRequest and
    keeps its IpAddressType, while setting the already-valid ipv4 on the same NLB succeeds."""
    elbv2 = ctx.client("elbv2")
    subnet_a, subnet_b, _vpc_id = _two_az_subnets(ctx)

    lb_name = _short_name(ctx, "sim2real-iptype-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=[subnet_a, subnet_b],
        Type="network",
        Scheme="internal",
        Tags=_managed_tags(ctx),
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )
    original_type = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["IpAddressType"]
    assert original_type == "ipv4", f"expected a freshly created NLB to start as ipv4, got {original_type!r}"

    # --- negative: dualstack-without-public-ipv4 is an ALB-only value; a Network
    # Load Balancer rejects it and its IpAddressType is left unchanged ---
    code, message = _error(
        lambda: elbv2.set_ip_address_type(LoadBalancerArn=lb_arn, IpAddressType="dualstack-without-public-ipv4")
    )
    assert code == "InvalidConfigurationRequest", (
        f"expected SetIpAddressType(dualstack-without-public-ipv4) on an NLB to be rejected with "
        f"InvalidConfigurationRequest, got {code!r}"
    )
    expected_message = "The specified IP address type is not supported on load balancers with type 'network'."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    unchanged_type = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["IpAddressType"]
    assert unchanged_type == "ipv4", (
        f"expected the rejected SetIpAddressType call to leave IpAddressType unchanged at ipv4, "
        f"got {unchanged_type!r}"
    )

    # --- positive control: a value that IS supported for a Network Load Balancer
    # succeeds on the same load balancer ---
    resp = elbv2.set_ip_address_type(LoadBalancerArn=lb_arn, IpAddressType="ipv4")
    assert resp["IpAddressType"] == "ipv4", (
        f"expected SetIpAddressType(ipv4) on the same NLB to succeed and echo ipv4, "
        f"got {resp['IpAddressType']!r}"
    )
    confirmed_type = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["IpAddressType"]
    assert confirmed_type == "ipv4", (
        f"expected DescribeLoadBalancers to confirm ipv4 after the accepted SetIpAddressType call, "
        f"got {confirmed_type!r}"
    )




def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    name = ctx.unique_name(prefix)
    return name[:max_len].rstrip("-")


def _managed_tags(ctx: Any) -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-iptype-"}]


def _two_az_subnets(ctx) -> tuple[str, str, str]:
    """Adopt the run's shared network when it has subnets in >=2 AZs; otherwise create a
    dedicated VPC + subnets so a freshly provisioned account (with no shared network) still runs
    this check instead of failing on an environment precondition."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            ids = list(by_az.values())
            return ids[0], ids[1], vpc_id
    return _create_dedicated_two_az_subnets(ctx, ec2)


def _create_dedicated_two_az_subnets(ctx, ec2: Any) -> tuple[str, str, str]:
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _managed_tags(ctx)}
    ])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not have >=2 available Availability Zones")

    subnet_ids: list[str] = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.90.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _managed_tags(ctx)}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids[0], subnet_ids[1], vpc_id


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
