"""create-duplicate-listener-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-duplicate-listener-rejected"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateListener on a protocol/port combination already used by the load balancer raises
    DuplicateListener; deleting the conflicting listener makes the identical call succeed, and the
    dead listener id stays unusable in the meantime."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids, sg_id = _create_vpc_and_subnets(ctx)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, [sg_id])

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_listener_if_present(elbv2, listener_arn))

    listeners_before = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    assert len(listeners_before) == 1, listeners_before

    code, message = _poll_for_duplicate_rejection(ctx, elbv2, lb_arn)
    # Real AWS's wire error code for this rejection is the short form "DuplicateListener" (no
    # "Exception" suffix), even though the elbv2 API model names the modeled exception class
    # DuplicateListenerException; assert on the actual wire code.
    assert code == "DuplicateListener", code
    assert message == f"A listener already exists on this port for this load balancer '{lb_arn}'", message

    # the forbidden effect did not happen: still exactly one listener on this load balancer
    listeners_after = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    assert len(listeners_after) == 1, listeners_after
    assert listeners_after[0]["ListenerArn"] == listener_arn, listeners_after

    # restore: remove the listener that occupied port 80, prove the id is now unusable (not just
    # absent from the list), then confirm the IDENTICAL rejected call now succeeds.
    #
    # ModifyListener requires the listener to exist, so it proves the deleted ARN is dead.
    elbv2.delete_listener(ListenerArn=listener_arn)
    _poll_until_gone(elbv2, lb_arn, listener_arn)

    dead_id_code, dead_id_message = _expect_error_code(lambda: elbv2.modify_listener(ListenerArn=listener_arn, Port=8081))
    assert dead_id_code == "ListenerNotFound", dead_id_code
    assert dead_id_message == f"Listener '{listener_arn}' not found", dead_id_message

    restored_arn = _poll_until_listener_creatable(elbv2, lb_arn)
    ctx.on_cleanup(lambda: _delete_listener_if_present(elbv2, restored_arn))

    listeners_restored = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    assert {listener["ListenerArn"] for listener in listeners_restored} == {restored_arn}, listeners_restored

    # positive control: a DIFFERENT port on the same load balancer is accepted
    other_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=8080,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_listener_if_present(elbv2, other_listener_arn))

    listeners_final = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    assert {listener["ListenerArn"] for listener in listeners_final} == {restored_arn, other_listener_arn}, (
        listeners_final
    )


# ===== helpers =====

def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{resource_type}-")}],
    }


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    reused = _find_reusable_vpc(ec2, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(CidrBlock="10.98.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.98.{i}.0/24", AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _find_reusable_vpc(ec2, *, ctx):
    """Reuse an existing VPC that already has subnets spanning >=2 AZs and a default security
    group, instead of always provisioning a fresh one. This check has no need for a dedicated
    VPC, but always creating one can exhaust the account's per-region VPC quota when many
    behavioral checks run back-to-back (VpcLimitExceeded)."""
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
        if len(by_az) < 2:
            continue
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"]
        if not sgs:
            continue
        return vpc_id, list(by_az.values())[:2], sgs[0]["GroupId"]
    return None


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"), Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_ids) -> str:
    elbv2 = ctx.client("elbv2")
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"), Subnets=subnet_ids, SecurityGroups=sg_ids,
        Scheme="internal", Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_for_lb_active(ctx, lb_arn)
    return lb_arn


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 300.0, interval_s: float = 5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return lb
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State'].get('Reason')}")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer did not reach active within {timeout_s}s")


def _expect_error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


def _duplicate_probe_actions() -> list:
    # Deliberately NOT the same DefaultActions as the listener already occupying the port: real
    # AWS treats a CreateListener whose parameters exactly match an existing listener as an
    # idempotent no-op replay (silent success), which would hide the duplicate-port rejection this
    # check exists to observe. A fixed-response action instead of forwarding guarantees the
    # request cannot be mistaken for a replay and must go through the real conflict check.
    return [{
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "duplicate-probe"},
    }]


def _delete_listener_if_present(elbv2, listener_arn: str) -> None:
    try:
        elbv2.delete_listener(ListenerArn=listener_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ListenerNotFound":
            raise


def _poll_for_duplicate_rejection(ctx, elbv2, lb_arn, timeout_s: float = 30.0, interval_s: float = 3.0):
    """Attempt a conflicting CreateListener call and return the rejection (code, message).

    One conflicting CreateListener (different DefaultActions, so it cannot be an idempotent
    replay); only throttling is retried; an unexpected success fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.create_listener(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=_duplicate_probe_actions())
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("Throttling", "ThrottlingException", "RequestLimitExceeded") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, exc.response["Error"].get("Message")
        else:
            raise AssertionError(
                "CreateListener for a port already used on this load balancer unexpectedly succeeded"
            )


def _poll_until_gone(elbv2, lb_arn, listener_arn: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """Independent-read confirmation that a deleted listener has actually left the list, not just
    that the DeleteListener call returned 200."""
    deadline = time.monotonic() + timeout_s
    while True:
        arns = {l["ListenerArn"] for l in elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]}
        if listener_arn not in arns:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"listener {listener_arn} still visible {timeout_s}s after DeleteListener")
        time.sleep(interval_s)


def _poll_until_listener_creatable(elbv2, lb_arn, timeout_s: float = 30.0, interval_s: float = 2.0) -> str:
    """Retry the identical (fixed-response, port 80) call that was rejected as DuplicateListener,
    now that the conflicting listener is gone. A transient DuplicateListener here would mean the
    delete has not fully propagated yet; any other rejection is a genuine failure to restore."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = elbv2.create_listener(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=_duplicate_probe_actions())
            return resp["Listeners"][0]["ListenerArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DuplicateListener" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
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
