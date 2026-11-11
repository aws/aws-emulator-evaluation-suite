"""delete-load-balancer-with-deletion-protection-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-load-balancer-with-deletion-protection-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLoadBalancer on a load balancer with deletion_protection.enabled=true is rejected
    with OperationNotPermitted and has no effect; after disabling protection the delete succeeds
    and the dead ARN 404s on both a read and a further mutation."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    arn = lb["LoadBalancerArn"]

    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=arn, Attributes=[{"Key": "deletion_protection.enabled", "Value": "true"}]
    )

    code, message = _error(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn))
    # Real AWS's ELBv2 API rejects the delete with the generic OperationNotPermitted code (not
    # ResourceInUse, which the service reserves for other in-use conflicts, e.g. a target group
    # still referenced by a listener rule).
    assert code == "OperationNotPermitted", (
        f"expected OperationNotPermitted while deletion protection is enabled, got {code!r}"
    )
    expected = f"Load balancer '{arn}' cannot be deleted because deletion protection is enabled"
    assert message == expected, f"MSG={message!r}"

    # The rejected delete must have had zero effect: an independent read still finds the LB.
    still_there = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert still_there["LoadBalancerArn"] == arn, (
        f"rejected delete should leave the load balancer in place, got {still_there!r}"
    )

    # Disabling protection must allow the delete to proceed (the cleanup below relies on this too).
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=arn, Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}]
    )
    elbv2.delete_load_balancer(LoadBalancerArn=arn)

    code_after, message_after = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn]))
    assert code_after == "LoadBalancerNotFound", f"expected the load balancer to be gone, got {code_after!r}"
    assert message_after == "One or more load balancers not found", f"MSG={message_after!r}"

    # A mutation on the dead ARN must fail as not-found too, not just a read.
    code_mutate, message_mutate = _error(
        lambda: elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=arn, Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}]
        )
    )
    assert code_mutate == "LoadBalancerNotFound", (
        f"expected a mutation on the deleted ARN to fail as not-found, got {code_mutate!r}"
    )
    assert message_mutate == f"Load balancer '{arn}' not found", f"MSG={message_mutate!r}"


# ===== helpers =====
_GONE = {"LoadBalancerNotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}
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


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _error(fn) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _default_vpc_and_subnets(ctx):
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
            return {"vpc_id": vpc_id, "subnet_ids": [s["SubnetId"] for s in chosen]}

    # No usable shared network (absent, or fewer than 2 AZs of subnets) — create our own rather than
    # depending on an ambient default that a freshly provisioned account may not have.
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv())
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[sid], Tags=_tags_kv())
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(sid)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Tags=_tags_kv())
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    # The check itself disables protection and deletes the LB on the happy path; this cleanup
    # covers an earlier failure (an already-deleted LB is LoadBalancerNotFound).
    ctx.on_cleanup(
        lambda: _safe(
            lambda: (
                elbv2.modify_load_balancer_attributes(
                    LoadBalancerArn=arn, Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}]
                ),
                elbv2.delete_load_balancer(LoadBalancerArn=arn),
            )
        )
    )
    return lb


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
