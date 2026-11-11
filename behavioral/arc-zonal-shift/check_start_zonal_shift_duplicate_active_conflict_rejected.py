"""start-zonal-shift-duplicate-active-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-zonal-shift-duplicate-active-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartZonalShift rejects a second concurrent shift for the same resource+AZ while the
    first is still ACTIVE, the first shift is left untouched, and after canceling it a new
    shift for the same resource+AZ succeeds (positive control)."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)

    first = arc.start_zonal_shift(
        resourceIdentifier=lb_arn, awayFrom=away_from, expiresIn="1h", comment="first-shift"
    )
    first_id = first["zonalShiftId"]
    ctx.on_cleanup(lambda: _cancel_if_active(arc, first_id))

    code, message = _error_detail(
        lambda: arc.start_zonal_shift(
            resourceIdentifier=lb_arn, awayFrom=away_from, expiresIn="1h", comment="second-shift"
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}: {message}"
    expected_message = "There's already an active zonal shift for that resource."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect: the original shift is unaffected -- still the sole ACTIVE shift for this AZ.
    items = arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
    active_for_az = [i for i in items if i["awayFrom"] == away_from and i["status"] == "ACTIVE"]
    assert len(active_for_az) == 1, f"expected exactly 1 ACTIVE shift for {away_from}, got {active_for_az!r}"
    assert active_for_az[0]["zonalShiftId"] == first_id, (
        f"expected the sole ACTIVE shift to be {first_id!r}, got {active_for_az[0]['zonalShiftId']!r}"
    )
    assert active_for_az[0]["comment"] == "first-shift", (
        f"expected comment 'first-shift', got {active_for_az[0]['comment']!r}"
    )

    # Positive control: after canceling the first shift, a new one for the same AZ succeeds.
    arc.cancel_zonal_shift(zonalShiftId=first_id)
    second = arc.start_zonal_shift(
        resourceIdentifier=lb_arn, awayFrom=away_from, expiresIn="30m", comment="after-cancel"
    )
    second_id = second["zonalShiftId"]
    ctx.on_cleanup(lambda: _cancel_if_active(arc, second_id))

    # Independent terminal read: the new shift is visible and ACTIVE at the destination, not
    # just in the StartZonalShift response.
    items_after = arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
    active_after = [i for i in items_after if i["awayFrom"] == away_from and i["status"] == "ACTIVE"]
    assert len(active_after) == 1, f"expected exactly 1 ACTIVE shift for {away_from}, got {active_after!r}"
    assert active_after[0]["zonalShiftId"] == second_id, (
        f"expected the sole ACTIVE shift to be {second_id!r}, got {active_after[0]['zonalShiftId']!r}"
    )


def _error_detail(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
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


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs and wait for ARC to auto-register it as a
    managed resource. Returns (load_balancer_arn, away_from_az_id)."""
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

    name = ctx.unique_name("sim2realarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    # A Network Load Balancer is not auto-discovered by ARC merely by spanning 2+ AZs -- it
    # must opt in to ARC zonal shift integration explicitly (confirmed against the real API
    # and https://docs.aws.amazon.com/r53recovery/latest/dg/arc-zonal-shift.resource-types.network-load-balancers.html).
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
            # Real AWS answers GetManagedResource with AccessDeniedException (not
            # ResourceNotFoundException) while ARC has not yet auto-discovered this load
            # balancer as a managed resource.
            pass
        time.sleep(2)
    if not resource or not resource.get("appliedWeights"):
        raise AssertionError(
            f"load balancer {lb_arn} was never registered as an ARC managed resource "
            "within 15 minutes"
        )
    away_from = sorted(resource["appliedWeights"])[0]
    return lb_arn, away_from


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
