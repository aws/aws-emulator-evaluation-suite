"""target-group-delete-blocked-while-referenced-then-freed-by-lb-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-group-delete-blocked-while-referenced-then-freed-by-lb-delete"
GROUP = "target-group-lifecycle"
SERVICES = ["elbv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last_exc = exc
            time.sleep(delays[min(attempt, len(delays) - 1)])
    raise last_exc


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises instead."""
    delays = [3, 6, 12, 24, 30]
    for attempt in range(5):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") not in _THROTTLE_CODES:
                return err.get("Code"), err.get("Message")
            time.sleep(delays[attempt])
            continue
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    raise AssertionError("still throttled after 5 attempts")


def _probe(fn):
    """(code, message) of the ClientError ``fn`` raises, or (None, None) when it succeeds.

    For polling toward a state that may still be the opposite of a refusal (success, or a
    different not-found code) without treating that as the unexpected case `_error` guards.
    """
    delays = [3, 6, 12, 24, 30]
    for attempt in range(5):
        try:
            fn()
            return None, None
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") not in _THROTTLE_CODES:
                return err.get("Code"), err.get("Message")
            time.sleep(delays[attempt])
    raise AssertionError("still throttled after 5 attempts")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last was {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """DeleteTargetGroup is refused with ResourceInUse while a listener's default action
    references the group, whose DescribeTargetGroups names the load balancer in LoadBalancerArns;
    deleting that load balancer empties LoadBalancerArns and lets the delete succeed.
    """
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    net = _setup_network(ctx, ec2)

    tg_name = ctx.unique_name("sim2real-behav-tg-")
    tg = _retry_throttled(lambda: elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=net["vpc_id"], TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": "target-group-release"}],
    ))["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    lb_name = ctx.unique_name("sim2real-behav-lb-")
    lb = _retry_throttled(lambda: elbv2.create_load_balancer(
        Name=lb_name, Subnets=net["subnet_ids"], Type="application", Scheme="internal",
        Tags=[{"Key": "sim2real", "Value": "target-group-release"}],
    ))["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _teardown_lb(elbv2, lb_arn))

    _retry_throttled(lambda: elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    ))

    # Before any delete: the group is in use, and DescribeTargetGroups already names the load
    # balancer referencing it.
    described = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert described["LoadBalancerArns"] == [lb_arn], (
        f"expected LoadBalancerArns=[{lb_arn!r}] while the listener still forwards to the group, "
        f"got {described['LoadBalancerArns']!r}"
    )

    in_use_code, in_use_message = _error(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    assert in_use_code == "ResourceInUse", f"expected resource-in-use error, got {in_use_code!r}"
    expected_in_use = f"Target group '{tg_arn}' is currently in use by a listener or a rule"
    assert in_use_message == expected_in_use, f"MESSAGE={in_use_message!r}"

    # The rejected delete left the group untouched, still naming the same load balancer.
    after_refusal = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert after_refusal["LoadBalancerArns"] == [lb_arn], (
        f"a rejected delete should not change LoadBalancerArns; got {after_refusal['LoadBalancerArns']!r}"
    )

    # Deleting the load balancer is the one thing that changes: its listener is cascaded away,
    # which is what releases the target group.
    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)

    def _lb_gone():
        return _probe(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn]))

    gone_code, gone_message = _poll_until(
        _lb_gone, lambda c: c[0] is not None, timeout_s=180, interval_s=3,
        description="load balancer reaching a not-found read after delete",
    )
    assert gone_code == "LoadBalancerNotFound", f"expected load-balancer not-found, got {gone_code!r}"
    assert gone_message == "One or more load balancers not found", f"MESSAGE={gone_message!r}"

    def _tg_released():
        return elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]["LoadBalancerArns"]

    released = _poll_until(
        _tg_released, lambda arns: arns == [], timeout_s=180, interval_s=3,
        description="target group's LoadBalancerArns emptying after the load balancer is gone",
    )
    assert released == [], f"expected LoadBalancerArns=[] once the load balancer is gone, got {released!r}"

    # Positive control: the identical delete that was refused earlier now succeeds.
    def _try_delete():
        return _probe(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    delete_code, _ = _poll_until(
        _try_delete, lambda c: c[0] is None, timeout_s=60, interval_s=5,
        description="target group becoming deletable once its load balancer is gone",
    )
    assert delete_code is None, f"target group still not deletable: {delete_code!r}"

    nf_code, nf_message = _error(lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]))
    assert nf_code == "TargetGroupNotFound", f"expected target-group not-found, got {nf_code!r}"
    assert nf_message == "One or more target groups not found", f"MESSAGE={nf_message!r}"


# ===== helpers =====

def _setup_network(ctx, ec2, num_subnets=2):
    """Create-or-adopt: use the shared network's subnets if it has enough across AZs, else a
    scratch VPC. A freshly provisioned account may have no shared network at all."""
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az = {}
        for s in sorted(subnets, key=lambda s: s["SubnetId"]):
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = [by_az[az] for az in sorted(by_az)][:num_subnets]
        if len(subnet_ids) >= num_subnets:
            return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}

    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": "target-group-release"}])
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.create_tags(Resources=[sid], Tags=[{"Key": "sim2real", "Value": "target-group-release"}])
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _teardown_lb(elbv2, arn):
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer in
# this VPC deletes asynchronously: its delete returns while its ENIs still sit in the subnet, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Wait (bounded) for the ENIs to
# go, retry inside the same window, and raise a final failure naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(5)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(5)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
