"""update-zonal-shift-extends-expiry."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-zonal-shift-extends-expiry"
GROUP = "state"
SERVICES = ["arc-zonal-shift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateZonalShift extends expiryTime and overwrites the comment of an ACTIVE shift in
    place, without changing its status, and the change is visible through GetManagedResource."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)

    shift = arc.start_zonal_shift(
        resourceIdentifier=lb_arn,
        awayFrom=away_from,
        expiresIn="1h",
        comment="sim2real-original-comment",
    )
    shift_id = shift["zonalShiftId"]
    ctx.on_cleanup(lambda: _cancel_if_active(arc, shift_id))
    original_expiry = shift["expiryTime"]

    updated = arc.update_zonal_shift(
        zonalShiftId=shift_id, expiresIn="3h", comment="sim2real-extended-comment"
    )
    assert updated["status"] == "ACTIVE"
    assert updated["comment"] == "sim2real-extended-comment"
    assert updated["expiryTime"] > original_expiry, "expiryTime did not move forward"

    resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
    matched = next(z for z in resource["zonalShifts"] if z["zonalShiftId"] == shift_id)
    assert matched["comment"] == "sim2real-extended-comment"
    assert matched["expiryTime"] == updated["expiryTime"]


# ===== helpers =====
def _cancel_if_active(arc, shift_id):
    try:
        arc.cancel_zonal_shift(zonalShiftId=shift_id)
    except arc.exceptions.ConflictException:
        pass
    except arc.exceptions.ResourceNotFoundException:
        pass


def _resolve_subnets(ctx, ec2):
    """Two subnets in distinct AZs, suitable for an internal NLB, in a VPC this check creates
    and deletes, so nothing depends on a default or pre-existing VPC."""
    azs = sorted(
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    )
    if len(azs) < 2:
        raise AssertionError("region does not have at least 2 available Availability Zones")

    vpc_name = ctx.unique_name("sim2real-arczs-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.201.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.201.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{vpc_name}-{i}"}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_subnet_with_retry(ec2, sid))
    return subnet_ids


def _delete_subnet_with_retry(ec2, subnet_id):
    """The NLB deleted just before this can leave ENIs attached to the subnet for a short window
    after the delete call returns; retry instead of leaking the subnet on the first DependencyViolation."""
    deadline = time.monotonic() + 45.0
    while True:
        try:
            _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
            return
        except Exception as e:  # noqa: BLE001 — retry on transient DependencyViolation only
            if "DependencyViolation" not in str(e) or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs, turn on its ARC zonal-shift integration, and
    wait for ARC to register it as a managed resource. Returns (load_balancer_arn,
    away_from_az_id)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")

    subnet_ids = _resolve_subnets(ctx, ec2)

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

    # ARC does not auto-discover Network Load Balancers: a load balancer only becomes an ARC
    # managed resource once zonal-shift integration is explicitly turned on
    # (https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.network-load-balancers.html).
    # Measured on real AWS: with this call, discovery completes in well under a minute; without
    # it, GetManagedResource answers AccessDeniedException forever and a poll would spin out.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "zonal_shift.config.enabled", "Value": "true"}],
    )

    deadline = time.monotonic() + 900.0
    resource = None
    while time.monotonic() < deadline:
        try:
            resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
            if resource.get("appliedWeights"):
                break
        except (arc.exceptions.ResourceNotFoundException, arc.exceptions.AccessDeniedException):
            # Real AWS answers an unregistered ARN with AccessDeniedException ("... is not a
            # managed resource for account ID ..."), not ResourceNotFoundException.
            resource = None
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
