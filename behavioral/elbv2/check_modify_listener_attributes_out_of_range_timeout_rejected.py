"""modify-listener-attributes-out-of-range-timeout-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-listener-attributes-out-of-range-timeout-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An NLB TCP listener rejects tcp.idle_timeout.seconds above the documented 60-6000 range
    with ValidationError, leaves the stored value unchanged, and still accepts an in-range value."""
    elbv2 = ctx.client("elbv2")
    subnet_a, subnet_b, vpc_id = _vpc_two_az_subnets(ctx)

    lb_name = _short_name(ctx, "sim2real-lattr-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="network", Scheme="internal",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )

    tg_name = _short_name(ctx, "sim2real-lattr-tg-", 32)
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="TCP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "Name", "Value": tg_name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="TCP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    def _current_timeout() -> str:
        attrs = elbv2.describe_listener_attributes(ListenerArn=listener_arn).get("Attributes", [])
        values = [a["Value"] for a in attrs if a["Key"] == "tcp.idle_timeout.seconds"]
        assert values, f"DescribeListenerAttributes reported no tcp.idle_timeout.seconds: {attrs!r}"
        return values[0]

    baseline = _current_timeout()
    assert baseline == "350", f"expected documented default of 350, got {baseline!r}"  # fixed API default, not account-adjustable

    # --- negative: 6001 is above the documented maximum of 6000; rejected, and the
    # stored attribute value is unchanged ---
    refused = _expect_error(
                  lambda: elbv2.modify_listener_attributes(
                      ListenerArn=listener_arn, Attributes=[{"Key": "tcp.idle_timeout.seconds", "Value": "6001"}]
        ),
                  ("ValidationError",),
                  contains=("tcp.idle_timeout.seconds",),
    )
    expected_message = "'tcp.idle_timeout.seconds' value '6001' must be between '60-6000' inclusive"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    after_reject = _current_timeout()
    assert after_reject == baseline, f"expected timeout unchanged at {baseline!r} after rejection, got {after_reject!r}"

    # --- positive control: an in-range value on the same listener succeeds and is
    # reflected by DescribeListenerAttributes ---
    resp = elbv2.modify_listener_attributes(
        ListenerArn=listener_arn, Attributes=[{"Key": "tcp.idle_timeout.seconds", "Value": "600"}]
    )
    updated = next(a["Value"] for a in resp["Attributes"] if a["Key"] == "tcp.idle_timeout.seconds")
    assert updated == "600", f"expected ModifyListenerAttributes response to reflect 600, got {updated!r}"
    after_accept = _current_timeout()
    assert after_accept == "600", f"expected DescribeListenerAttributes to reflect 600, got {after_accept!r}"




def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _ignore_not_found(fn: Callable[[], Any]) -> None:
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


def _vpc_two_az_subnets(ctx) -> tuple[str, str, str]:
    """Use the default VPC's default-for-az subnets (account baseline, read only) when they span
    >=2 AZs; otherwise create a VPC and subnets of this run's own. Never adopt another VPC."""
    ec2 = ctx.client("ec2")
    reused = _default_vpc_subnets(ec2, ctx=ctx)
    if reused:
        subnet_a, subnet_b, vpc_id = reused
        return subnet_a, subnet_b, vpc_id

    vpc_name = ctx.unique_name("sim2real-lattr-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/16", TagSpecifications=[_tag_spec("vpc", vpc_name)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_name = ctx.unique_name(f"sim2real-lattr-subnet-{i}-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.95.{i}.0/24", AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec("subnet", subnet_name)],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _ignore_not_found(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        raise AssertionError(f"need subnets in >=2 Availability Zones, got {len(subnet_ids)}")
    return subnet_ids[0], subnet_ids[1], vpc_id


def _default_vpc_subnets(ec2, *, ctx) -> tuple[str, str, str] | None:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            {"Name": "state", "Values": ["available"]},
        ]
    )["Subnets"]
    by_az: dict[str, str] = {}
    for s in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        return None
    ids = list(by_az.values())
    return ids[0], ids[1], vpc_id


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


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
