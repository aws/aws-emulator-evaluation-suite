"""duplicate-listener-port-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-listener-port-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second listener on the same load balancer + port is rejected with DuplicateListener and
    leaves no trace; once the conflicting listener is removed the identical request succeeds."""
    net = _vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    tg = _create_target_group(ctx, net["vpc_id"])
    # Use a *different* target group for the duplicate attempt below. On real AWS, CreateListener
    # treats a request whose parameters (Port, Protocol, DefaultActions, ...) exactly match an
    # already-existing listener as an idempotent no-op: it silently returns success (describing the
    # pre-existing listener) instead of raising DuplicateListener. Varying the DefaultActions'
    # TargetGroupArn between the two attempts guarantees the requests differ, so the conflicting-port
    # check is actually evaluated (and rejects) instead of short-circuiting via the idempotent path.
    tg2 = _create_target_group(ctx, net["vpc_id"])

    # The duplicate-port conflict check is enforced against the load balancer's settled
    # provisioning state. While the load balancer is still "provisioning" (immediately after
    # CreateLoadBalancer) a second listener on an already-used port can slip past the conflict
    # check uncontested, so wait for "active" before exercising it.
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    listener1_arn = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener1_arn)))

    # The first listener's registration can lag slightly behind the CreateListener response
    # (eventual consistency across the service's internal replicas). Confirm it is actually
    # visible via DescribeListeners before probing for the duplicate-port rejection, otherwise
    # the second create can race ahead of the conflict check and spuriously succeed.
    _poll_until(
        lambda: elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"],
        lambda listeners: any(items["Port"] == 80 for items in listeners),
        timeout_s=30,
        interval_s=2,
    )

    # Even once DescribeListeners shows the port taken, the write-path conflict check can lag a
    # beat further behind that read path: retry the duplicate CreateListener attempt until it is
    # actually rejected, cleaning up (and retrying past) any stray listener a still-racing
    # attempt manages to create in the meantime.
    code, message = _poll_until_duplicate_rejected(ctx, elbv2, lb["LoadBalancerArn"], tg2["TargetGroupArn"])
    assert code == "DuplicateListener", f"expected DuplicateListener, got {code!r}"
    assert message == (
        f"A listener already exists on this port for this load balancer '{lb['LoadBalancerArn']}'"
    ), message

    # Effect absent: an independent read (not the rejected call's own response) still shows
    # exactly the original listener on port 80, forwarding to tg -- the rejected duplicate never
    # took effect.
    listeners_after_reject = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
    port_80 = [x for x in listeners_after_reject if x["Port"] == 80]
    assert len(port_80) == 1, f"expected exactly 1 listener on port 80 after rejection, got {port_80}"
    assert port_80[0]["ListenerArn"] == listener1_arn, "the rejected duplicate replaced the original listener"
    assert port_80[0]["DefaultActions"][0]["TargetGroupArn"] == tg["TargetGroupArn"], (
        f"expected port 80 to still forward to {tg['TargetGroupArn']!r}, "
        f"got {port_80[0]['DefaultActions'][0]['TargetGroupArn']!r}"
    )

    # Restore: the port-conflict is a state-forbids rejection, not an always-invalid input, so it
    # must be shown to lift. Delete the original listener, confirm via an independent read that
    # the port is actually free (not just that the delete call itself returned 200), then replay
    # the *identical* request that was rejected a moment ago and demand it now succeeds.
    elbv2.delete_listener(ListenerArn=listener1_arn)
    _poll_until(
        lambda: elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"],
        lambda listeners: not any(x["Port"] == 80 for x in listeners),
        timeout_s=30,
        interval_s=2,
    )

    listener2_arn = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg2["TargetGroupArn"]}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener2_arn)))

    listeners_final = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
    port_80_final = [x for x in listeners_final if x["Port"] == 80]
    assert len(port_80_final) == 1, f"expected exactly 1 listener on port 80 after restore, got {port_80_final}"
    assert port_80_final[0]["ListenerArn"] == listener2_arn, (
        f"expected the restored listener to be {listener2_arn!r}, got {port_80_final[0]['ListenerArn']!r}"
    )
    assert port_80_final[0]["DefaultActions"][0]["TargetGroupArn"] == tg2["TargetGroupArn"], (
        f"expected port 80 to now forward to {tg2['TargetGroupArn']!r}, "
        f"got {port_80_final[0]['DefaultActions'][0]['TargetGroupArn']!r}"
    )


# ===== helpers =====
_GONE = {"LoadBalancerNotFound", "TargetGroupNotFound", "ListenerNotFound",
         "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}
_BUSY = {"ResourceInUse", "ResourceInUseException"}


def _safe(fn, timeout_s=120.0):
    """Teardown: done once the resource is gone; retries while a dependency is still being released."""
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _GONE:
                return
            if code not in _BUSY or _time.monotonic() >= deadline:
                raise
        _time.sleep(2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time as _t

    deadline = _t.monotonic() + timeout_s
    last = None
    while _t.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _t.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_lb_active(ctx, arn, timeout_s=180, interval_s=5):
    elbv2 = ctx.client("elbv2")
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _poll_until_duplicate_rejected(ctx, elbv2, lb_arn, tg_arn, timeout_s=30.0, interval_s=2.0):
    """Retry the duplicate-port CreateListener attempt (using a distinct TargetGroupArn from the
    original listener, so the request can't be short-circuited as an idempotent no-op) until it is
    rejected with DuplicateListener; return the last (code, message). If the conflict check hasn't caught up yet and the call
    spuriously succeeds, clean up the stray listener it created and keep retrying within the
    budget."""
    import time as _t

    deadline = _t.monotonic() + timeout_s
    last_code = last_message = None
    while _t.monotonic() < deadline:
        try:
            resp = elbv2.create_listener(
                LoadBalancerArn=lb_arn,
                Protocol="HTTP",
                Port=80,
                DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
            )
            stray_arn = resp["Listeners"][0]["ListenerArn"]
            ctx.on_cleanup(lambda a=stray_arn: _safe(lambda: elbv2.delete_listener(ListenerArn=a)))
            last_code = last_message = None
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            last_message = e.response["Error"].get("Message")
            if last_code == "DuplicateListener":
                return last_code, last_message
        _t.sleep(interval_s)
    return last_code, last_message


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _vpc_and_subnets(ctx):
    """Reuse any existing VPC (default or not) that already spans >=2 AZs, so the check does not
    depend on an ambient default VPC being present -- a freshly provisioned account may not have
    one. Only create a fresh VPC when nothing reusable exists, to avoid needlessly spending the
    account's per-region VPC quota."""
    ec2 = ctx.client("ec2")
    reused = _reusable_vpc_and_subnets(ec2, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(
        CidrBlock="10.97.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError("region does not have at least 2 available availability zones")
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.97.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _reusable_vpc_and_subnets(ec2, *, ctx):
    try:
        vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    except ClientError:
        return None
    vpcs = sorted(vpcs, key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())[:2]}
    return None


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
    return tg


# Network teardown: load balancers and similar resources delete asynchronously and leave ENIs in
# the subnet or security group, so an immediate delete fails with DependencyViolation. Wait for
# the ENIs (bounded, shared by all of one check's network deletes), then retry within the window.
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
