"""forward-to-incompatible-target-group-protocol-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forward-to-incompatible-target-group-protocol-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An HTTP listener on an Application Load Balancer cannot forward to a target group whose
    protocol is TCP (an NLB-only protocol): CreateListener is rejected with IncompatibleProtocols,
    and the identical call succeeds once the target group's protocol matches the listener."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _setup_network(ctx)
    lb = _create_alb(ctx, subnet_ids)
    tcp_tg = _create_target_group(ctx, vpc_id, Protocol="TCP", Port=80)

    code, message = _error_code(
        lambda: elbv2.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tcp_tg["TargetGroupArn"]}],
        )
    )
    assert code == "IncompatibleProtocols", f"expected IncompatibleProtocols, got {code!r}"
    assert message == (
        "The listener and the following target groups have incompatible protocols: "
        f"{tcp_tg['TargetGroupArn']}"
    ), message

    # No listener should have been created on the load balancer as a result.
    listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
    assert listeners == [], f"a listener should not exist after the rejected CreateListener: {listeners}"

    # Positive control: the identical call succeeds once the target group's protocol is HTTP.
    # Without this, the rejection above is indistinguishable from a target whose CreateListener is
    # simply broken and refuses every call regardless of target group protocol.
    http_tg = _create_target_group(ctx, vpc_id, Protocol="HTTP", Port=80)
    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": http_tg["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    described = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]
    assert described["DefaultActions"][0]["TargetGroupArn"] == http_tg["TargetGroupArn"], described


# ===== helpers =====
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-elbv2"},
]


# Not-found codes a teardown treats as already deleted; every other error raises.
_GONE = frozenset({
    "ListenerNotFound", "LoadBalancerNotFound", "TargetGroupNotFound",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
})


def _teardown(fn):
    """Run one teardown call: a resource already gone is fine; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE:
            raise


def _error_code(fn):
    """Return the ClientError (code, message); an unexpected success raises, since accepting a call AWS
    refuses is a stronger failure than a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected CreateListener to be rejected, but it SUCCEEDED: {result!r}")


def _setup_network(ctx, num_subnets=2):
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        per_az = {}
        for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
            per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
        subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
        if len(subnet_ids) >= min(num_subnets, 2):
            return vpc_id, subnet_ids

    # No usable shared network in this account/region: create the minimal network ourselves rather
    # than failing on an environment assumption.
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=_TAGS + [{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")}],
    )
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az,
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Type="application", Scheme="internal", Tags=list(_TAGS),
    )
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip", "Tags": list(_TAGS)}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_target_group_when_free(elbv2, arn)))
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
