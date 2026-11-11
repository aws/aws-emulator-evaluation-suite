"""concurrent-start-zonal-shift-exactly-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-start-zonal-shift-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["arc-zonal-shift"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

# ConflictExceptionReason values the Smithy model documents for a second StartZonalShift racing
# an already-active shift for the same resource+AZ, as opposed to the model's other reasons
# (AutoshiftEnabled, the PracticeConfiguration* family, ZonalShiftStatusNotActive) which describe
# unrelated conflicts and would mean a racer was rejected for the wrong reason.
_RACE_CONFLICT_REASONS = {"ZonalShiftAlreadyExists", "SimultaneousZonalShiftsConflict"}


#: GetManagedResource's AccessDeniedException messages for a load balancer ARC has not registered
#: yet; both are answered on real AWS while the registration is pending.
_NOT_YET_MANAGED = ("is not a managed resource", "Requested resource is not available")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Firing several concurrent StartZonalShift calls for the same resource+AZ yields exactly
    one ACTIVE winner; every other racer is rejected with ConflictException (the 'only one
    active shift per resource+AZ' invariant holds under contention)."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)

    def attempt(i):
        from botocore.exceptions import ClientError

        try:
            resp = arc.start_zonal_shift(
                resourceIdentifier=lb_arn,
                awayFrom=away_from,
                expiresIn="30m",
                comment=f"race-{i}",
            )
            return ("ok", resp)
        except ClientError as e:
            error = e.response["Error"]
            reason = error.get("reason") or error.get("Reason") or e.response.get("reason")
            return ("error", (error["Code"], reason, error.get("Message")))

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {successes}"
    assert len(errors) == 4, f"expected 4 rejected racers, got {len(errors)}"
    codes = [code for code, _reason, _message in errors]
    reasons = [reason for _code, reason, _message in errors]
    assert all(code == "ConflictException" for code in codes), errors
    expected = "There's already an active zonal shift for that resource."
    assert all(message == expected for _code, _reason, message in errors), errors
    assert all(reason in _RACE_CONFLICT_REASONS for reason in reasons), (
        f"expected every racer's ConflictException.reason in {_RACE_CONFLICT_REASONS}, got {reasons}"
    )

    winner_id = successes[0]["zonalShiftId"]
    ctx.on_cleanup(lambda: _cancel_if_active(arc, winner_id))

    # Effect: exactly one ACTIVE shift exists for this resource+AZ afterwards.
    items = arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
    active_for_az = [i for i in items if i["awayFrom"] == away_from and i["status"] == "ACTIVE"]
    assert len(active_for_az) == 1
    assert active_for_az[0]["zonalShiftId"] == winner_id


def _cancel_if_active(arc, shift_id):
    try:
        arc.cancel_zonal_shift(zonalShiftId=shift_id)
    except arc.exceptions.ConflictException:
        pass
    except arc.exceptions.ResourceNotFoundException:
        pass


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs, opt it in to ARC zonal shift integration, and
    wait for ARC to register it as a managed resource. Returns (load_balancer_arn,
    away_from_az_id)."""
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
        Tags=TAGS_KV,
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    def _delete_nlb():
        # Wait it out, so the NLB's network interfaces leave the shared network's subnets.
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        elbv2.get_waiter("load_balancers_deleted").wait(
            LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_delete_nlb)
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    # ARC does NOT auto-discover a Network Load Balancer -- per the resource-type doc
    # (arc-zonal-shift.resource-types.network-load-balancers), zonal shift integration is an
    # explicit opt-in load-balancer attribute. Without this, GetManagedResource never succeeds
    # no matter how long you poll.
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
        except arc.exceptions.ResourceNotFoundException:
            pass
        except arc.exceptions.AccessDeniedException as e:
            # Real AWS answers GetManagedResource with AccessDeniedException, not
            # ResourceNotFoundException, for a load balancer ARC has not (yet) registered as a
            # managed resource -- GetManagedResource's own model lists both error shapes.
            # Anything else (a genuine permission denial) must not be swallowed in a retry loop.
            if not any(m in e.response["Error"].get("Message", "") for m in _NOT_YET_MANAGED):
                raise
        time.sleep(2)
    if not resource or not resource.get("appliedWeights"):
        raise AssertionError(
            f"load balancer {lb_arn} was never registered as an ARC managed resource within "
            "900s of enabling zonal_shift.config.enabled"
        )
    away_from = sorted(resource["appliedWeights"])[0]
    return lb_arn, away_from


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
