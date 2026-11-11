"""start-zonal-shift-invalid-expires-in-format-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-zonal-shift-invalid-expires-in-format-rejected"
GROUP = "errors"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartZonalShift refuses an expiresIn that fits the 2-5 character length but not the
    ^([1-9][0-9]*)(m|h)$ pattern with ValidationException and creates no shift; a well-formed
    expiresIn still succeeds (positive control)."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)

    code, message = _error_detail(
        lambda: arc.start_zonal_shift(
            resourceIdentifier=lb_arn,
            awayFrom=away_from,
            expiresIn="10d",
            comment="invalid-expires-in-attempt",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    expected_message = (
        "1 validation error detected: Value at 'expiresIn' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ([1-9][0-9]*)(m|h)"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect: no shift was created for the resource.
    items = arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
    assert items == [], f"expected no shifts to have been created, got {items}"

    # Positive control: a well-formed expiresIn is accepted.
    started = arc.start_zonal_shift(
        resourceIdentifier=lb_arn, awayFrom=away_from, expiresIn="30m", comment="valid-expires-in"
    )
    shift_id = started["zonalShiftId"]
    ctx.on_cleanup(lambda: _cancel_if_active(arc, shift_id))
    assert started["status"] == "ACTIVE"

    # Terminal read: independent of the mutating call, via list_zonal_shifts.
    listed = arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
    match = next((s for s in listed if s["zonalShiftId"] == shift_id), None)
    assert match is not None, f"expected shift {shift_id} in list_zonal_shifts, got {listed}"
    assert match["status"] == "ACTIVE", f"expected ACTIVE, got {match['status']!r}"


# ===== helpers =====
# The AccessDeniedException messages real AWS answers GetManagedResource with while ARC has not
# yet registered a load balancer as a managed resource.
_UNREGISTERED_DENIALS = ("is not a managed resource", "Requested resource is not available.")


def _error_detail(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because
    accepting a call AWS refuses is a different failure from answering it with the wrong code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cancel_if_active(arc, shift_id):
    try:
        arc.cancel_zonal_shift(zonalShiftId=shift_id)
    except arc.exceptions.ConflictException:
        pass
    except arc.exceptions.ResourceNotFoundException:
        pass


def _poll_target_healthy(elbv2, tg_arn, target_id, timeout_s=280.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
        descs = resp["TargetHealthDescriptions"]
        if descs:
            last = descs[0]["TargetHealth"]["State"]
            if last == "healthy":
                return
        time.sleep(interval_s)
    raise AssertionError(f"backend target never reached healthy within {timeout_s}s, last={last!r}")


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs, with a registered healthy target, and wait
    for ARC to auto-register it as a managed resource. Returns (load_balancer_arn,
    away_from_az_id).

    ARC zonal shift only auto-discovers a load balancer once it has registered, healthy targets to
    shift traffic away from; a bare NLB with no target group is never discovered, and real AWS
    answers GetManagedResource with AccessDeniedException ("... is not a managed resource ...")
    indefinitely instead.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ARC managed load balancer")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 Availability Zones in this region")
    subnet_ids = [by_az[az] for az in sorted(by_az)[:2]]

    sg_name = ctx.unique_name("sim2realarczssg")[:32].strip("-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name, Description="sim2real ARC backend ALB ingress", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": ctx.network().cidr}]}],
    )

    backend_name = ctx.unique_name("sim2realarczsbe")[:32].strip("-")
    backend_arn = elbv2.create_load_balancer(
        Name=backend_name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        SecurityGroups=[sg_id],
        Tags=[{"Key": "Name", "Value": backend_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=backend_arn))
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[backend_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    backend_listener_arn = elbv2.create_listener(
        LoadBalancerArn=backend_arn,
        Port=80,
        Protocol="HTTP",
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
            }
        ],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=backend_listener_arn))

    tg_name = ctx.unique_name("sim2realarczstg")[:32].strip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        TargetType="alb",
        Protocol="TCP",
        Port=80,
        VpcId=vpc_id,
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=10,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    name = ctx.unique_name("sim2realarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    # ARC never discovers a Network Load Balancer as a managed resource unless zonal shift
    # integration is explicitly enabled on the load balancer's own attributes (AWS docs:
    # "Network Load Balancers" under ARC zonal shift resource types) — this is an opt-in
    # step, not automatic auto-discovery.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "zonal_shift.config.enabled", "Value": "true"}],
    )
    nlb_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Port=80,
        Protocol="TCP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=nlb_listener_arn))

    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": backend_arn}])
    ctx.on_cleanup(lambda: elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": backend_arn}]))
    _poll_target_healthy(elbv2, tg_arn, backend_arn, timeout_s=280.0)

    deadline = time.monotonic() + 900.0
    resource = None
    while time.monotonic() < deadline:
        try:
            resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
            if resource.get("appliedWeights"):
                break
        except arc.exceptions.ResourceNotFoundException:
            pass
        except arc.exceptions.AccessDeniedException as e:
            # Real AWS answers GetManagedResource with AccessDeniedException, not
            # ResourceNotFoundException, while the load balancer has not yet been
            # auto-discovered as a managed resource.
            if not any(m in str(e) for m in _UNREGISTERED_DENIALS):
                raise
        time.sleep(2)
    if not resource or not resource.get("appliedWeights"):
        raise AssertionError(
            f"load balancer {lb_arn} was never registered as an ARC managed resource "
            "within 15 minutes"
        )
    away_from = sorted(resource["appliedWeights"])[0]
    return lb_arn, away_from


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: a load balancer deletes
# asynchronously, so an immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Wait (bounded)
# for the ENIs, retry DependencyViolation in the same window, then raise naming the ENIs still attached.
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
