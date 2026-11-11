"""start-zonal-shift-invalid-az-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-zonal-shift-invalid-az-rejected"
GROUP = "errors"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartZonalShift rejects an awayFrom value that is not one of the resource's actual
    Availability Zones with ValidationException; no shift is created for the resource, and
    starting a shift for one of the resource's real AZs still succeeds (positive control)."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)

    code, message = _error_detail(
        lambda: arc.start_zonal_shift(
            resourceIdentifier=lb_arn,
            awayFrom="not-a-real-az-id",
            expiresIn="1h",
            comment="invalid-az-attempt",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    expected_message = "Invalid availability zone."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect: no shift was created for the resource. Read through GetManagedResource -- a different
    # operation than the one that mutated -- not ListZonalShifts, which real AWS does not reliably
    # populate for this resource.
    active = arc.get_managed_resource(resourceIdentifier=lb_arn).get("zonalShifts", [])
    assert active == [], f"expected no shifts to have been created, got {active}"

    # Positive control: a real AZ for this resource is accepted.
    started = arc.start_zonal_shift(
        resourceIdentifier=lb_arn, awayFrom=away_from, expiresIn="30m", comment="valid-az"
    )
    ctx.on_cleanup(lambda: _cancel_if_active(arc, started["zonalShiftId"]))
    assert started["status"] == "ACTIVE", f"expected ACTIVE, got {started['status']!r}"

    # Independent read at the destination: the accepted shift is visible and ACTIVE.
    _wait_for_shift_active(arc, lb_arn, started["zonalShiftId"])


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


def _wait_for_shift_active(arc, lb_arn, shift_id, timeout_s=60.0, interval_s=5.0):
    """Poll GetManagedResource until shift_id is listed among the resource's zonalShifts with
    its weight shift APPLIED (not just recorded). A bounded retry, not an assumption of
    immediate consistency. GetManagedResource.zonalShifts entries carry `appliedStatus`
    (APPLIED|NOT_APPLIED), not a lifecycle `status` field -- confirmed against the real
    botocore service model, not guessed."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        active = arc.get_managed_resource(resourceIdentifier=lb_arn).get("zonalShifts", [])
        last = {z["zonalShiftId"]: z["appliedStatus"] for z in active}
        if last.get(shift_id) == "APPLIED":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"shift {shift_id} never appeared APPLIED in GetManagedResource.zonalShifts "
        f"{last!r} {timeout_s}s after StartZonalShift"
    )


def _resolve_vpc_and_subnets(ec2, ctx):
    """Adopt the shared network's subnets if it spans >=2 AZs; otherwise create a minimal
    private VPC + subnets. A freshly provisioned account may have no shared network at all, so
    the check must not depend on one being ambiently present."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return [by_az[az] for az in sorted(by_az)[:2]]

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose 2 available Availability Zones to build a managed NLB")

    tag = ctx.unique_name("sim2realarczs-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.221.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.221.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs, opt it into ARC zonal shift via the
    `zonal_shift.config.enabled` load-balancer attribute (NLBs are NOT auto-discovered --
    this explicit opt-in is a real-AWS prerequisite: without it,
    GetManagedResource answers AccessDeniedException forever, never ResourceNotFoundException-
    then-success), and wait for ARC to pick it up as a managed resource. Returns
    (load_balancer_arn, away_from_az_id)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")

    subnet_ids = _resolve_vpc_and_subnets(ec2, ctx)

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
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "zonal_shift.config.enabled", "Value": "true"}],
    )

    deadline = time.monotonic() + 300.0
    resource = None
    while time.monotonic() < deadline:
        try:
            resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
            if resource.get("appliedWeights"):
                break
        except arc.exceptions.ResourceNotFoundException:
            pass
        except arc.exceptions.AccessDeniedException as e:
            # Before ARC has auto-registered the LB, GetManagedResource answers
            # AccessDeniedException ("... is not a managed resource for account ID ...")
            # rather than ResourceNotFoundException. Any other AccessDeniedException (a genuine
            # permissions problem) must still surface.
            if not any(m in str(e) for m in _UNREGISTERED_DENIALS):
                raise
        time.sleep(2)
    if not resource or not resource.get("appliedWeights"):
        raise AssertionError(
            f"load balancer {lb_arn} was never registered as an ARC managed resource "
            "within 5 minutes of enabling zonal_shift.config.enabled"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
