"""deploy-ec2-capacity-reservation-and-fleet-lifecycle."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ec2-capacity-reservation-and-fleet-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


_INSTANCE_TYPE = "t3.micro"
_PLATFORM = "Linux/UNIX"

def _usable_az(ec2) -> str:
    """An AZ that both offers ``_INSTANCE_TYPE`` and is currently available."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {_INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _template(az: str, tag_value: str) -> str:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Reservation": {
                "Type": "AWS::EC2::CapacityReservation",
                "Properties": {
                    "InstanceType": _INSTANCE_TYPE,
                    "InstancePlatform": _PLATFORM,
                    "InstanceCount": 1,
                    "AvailabilityZone": az,
                    "EndDateType": "unlimited",
                    "TagSpecifications": [{"ResourceType": "capacity-reservation", "Tags": t}],
                },
            },
            "Fleet": {
                "Type": "AWS::EC2::CapacityReservationFleet",
                "Properties": {
                    "InstanceTypeSpecifications": [{
                        "InstanceType": _INSTANCE_TYPE,
                        "AvailabilityZone": az,
                        "InstancePlatform": _PLATFORM,
                        "Weight": 1.0,
                        "Priority": 1,
                    }],
                    "TotalTargetCapacity": 1,
                    "AllocationStrategy": "prioritized",
                    "InstanceMatchCriteria": "open",
                    "TagSpecifications": [{"ResourceType": "capacity-reservation-fleet",
                                           "Tags": t}],
                },
            },
        },
        "Outputs": {
            "ReservationId": {"Value": {"Ref": "Reservation"}},
            "ReservationArn": {"Value": {"Fn::GetAtt": ["Reservation", "CapacityReservationArn"]}},
            "FleetId": {"Value": {"Ref": "Fleet"}},
        },
    })


def _poll_fleet_state(ec2, fleet_id: str, want: set[str], *, timeout_s: float = 400.0) -> dict[str, Any]:
    """Poll DescribeCapacityReservationFleets until ``State`` lands in ``want``."""
    deadline = time.monotonic() + timeout_s
    fleet = None
    while True:
        fleet = ec2.describe_capacity_reservation_fleets(
            CapacityReservationFleetIds=[fleet_id])["CapacityReservationFleets"][0]
        if fleet["State"] in want:
            return fleet
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"fleet {fleet_id} still {fleet['State']!r} after {timeout_s}s, expected one of {want!r}"
            )
        time.sleep(5)


def _poll_reservation_state(ec2, res_id: str, want: set[str], *, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    res = None
    while True:
        res = ec2.describe_capacity_reservations(CapacityReservationIds=[res_id])["CapacityReservations"][0]
        if res["State"] in want:
            return res
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"reservation {res_id} still {res['State']!r} after {timeout_s}s, expected one of {want!r}"
            )
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A standalone EC2 capacity reservation and a capacity reservation fleet CloudFormation
    declares are each really active in EC2, the fleet really fulfills its own reservation, and
    DeleteStack cancels all three (fleet, its reservation and the standalone one).
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    az = _usable_az(ec2)
    name = ctx.unique_name("sim2real-xsvc-capres-")
    tag_value = ctx.unique_name("sim2real-xsvc-capres-res-")
    tag_filter = [{"Name": "tag:sim2real-res", "Values": [tag_value]}]
    stack_id = create_stack(ctx, cfn, name, _template(az, tag_value))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"capacity-reservation stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    res_id, fleet_id = out["ReservationId"], out["FleetId"]

    # Refs against independent reads: the reservation and fleet carrying this run's template tag.
    tagged = [r["CapacityReservationId"] for r in paginate(
        ec2, "describe_capacity_reservations", "CapacityReservations", Filters=tag_filter)]
    assert tagged == [res_id], f"reservations tagged {tag_value!r}: {tagged!r}, Ref {res_id!r}"
    tagged = [f["CapacityReservationFleetId"] for f in paginate(
        ec2, "describe_capacity_reservation_fleets", "CapacityReservationFleets",
        Filters=tag_filter)]
    assert tagged == [fleet_id], f"fleets tagged {tag_value!r}: {tagged!r}, Ref {fleet_id!r}"

    # 1. the standalone reservation's Ref is its primary identifier, and EC2 reports it active
    # with the template's properties.
    res = ec2.describe_capacity_reservations(CapacityReservationIds=[res_id])["CapacityReservations"][0]
    assert res["CapacityReservationId"] == res_id, (
        f"Ref {res_id!r} does not match the reservation id EC2 reports: {res['CapacityReservationId']!r}"
    )
    assert (res["InstanceType"], res["InstancePlatform"], res["AvailabilityZone"], res["State"]) == (
        _INSTANCE_TYPE, _PLATFORM, az, "active"
    ), (
        f"reservation read back as "
        f"{(res['InstanceType'], res['InstancePlatform'], res['AvailabilityZone'], res['State'])!r}, "
        f"expected {(_INSTANCE_TYPE, _PLATFORM, az, 'active')!r}"
    )
    got = (res["TotalInstanceCount"], res["EndDateType"])
    assert got == (1, "unlimited"), f"reservation (TotalInstanceCount, EndDateType) {got!r}"
    assert res["CapacityReservationArn"] == out["ReservationArn"], (
        f"GetAtt CapacityReservationArn {out['ReservationArn']!r} disagrees with "
        f"DescribeCapacityReservations {res['CapacityReservationArn']!r}"
    )

    # 2. the fleet's Ref is its primary identifier, EC2 fulfills it (not merely accepts it), and
    # the fleet's own reservation is a real, separate, active CapacityReservation.
    fleet = _poll_fleet_state(ec2, fleet_id, {"active"})
    assert fleet["CapacityReservationFleetId"] == fleet_id, (
        f"Ref {fleet_id!r} does not match the fleet id EC2 reports: {fleet['CapacityReservationFleetId']!r}"
    )
    got = (fleet["TotalTargetCapacity"], fleet["AllocationStrategy"],
           fleet["InstanceMatchCriteria"])
    assert got == (1, "prioritized", "open"), f"fleet read back as {got!r}"
    specs = [(s["InstanceType"], s["AvailabilityZone"], s["InstancePlatform"], s["Weight"],
              s["Priority"]) for s in fleet["InstanceTypeSpecifications"]]
    want_specs = [(_INSTANCE_TYPE, az, _PLATFORM, 1.0, 1)]
    assert specs == want_specs, f"fleet InstanceTypeSpecifications {specs!r}, expected {want_specs!r}"

    fleet_reservations = paginate(
        ec2, "describe_capacity_reservations", "CapacityReservations",
        Filters=[{"Name": "capacity-reservation-fleet-id", "Values": [fleet_id]}],
    )
    assert len(fleet_reservations) == 1, (
        f"fleet {fleet_id} has {len(fleet_reservations)} underlying reservation(s), expected exactly 1: "
        f"{fleet_reservations!r}"
    )
    fr = fleet_reservations[0]
    assert (fr["InstanceType"], fr["AvailabilityZone"], fr["State"]) == (_INSTANCE_TYPE, az, "active"), (
        f"fleet's own reservation is "
        f"{(fr['InstanceType'], fr['AvailabilityZone'], fr['State'])!r}, expected "
        f"{(_INSTANCE_TYPE, az, 'active')!r}"
    )
    assert fr["CapacityReservationId"] != res_id, (
        "the fleet's own reservation must be a different object from the standalone reservation"
    )

    # 3. DeleteStack cancels the standalone reservation, the fleet, and the fleet's own
    # reservation -- three distinct EC2 objects, each verified by its own read.
    delete_stack(cfn, stack_id)

    gone_res = _poll_reservation_state(ec2, res_id, {"cancelled"})
    assert gone_res["State"] == "cancelled", (
        f"standalone reservation {res_id} is {gone_res['State']!r} after delete-stack, expected 'cancelled'"
    )

    gone_fleet = _poll_fleet_state(ec2, fleet_id, {"cancelled"})
    assert gone_fleet["State"] == "cancelled", (
        f"fleet {fleet_id} is {gone_fleet['State']!r} after delete-stack, expected 'cancelled'"
    )

    gone_fr = _poll_reservation_state(ec2, fr["CapacityReservationId"], {"cancelled"})
    assert gone_fr["State"] == "cancelled", (
        f"fleet's own reservation {fr['CapacityReservationId']} is {gone_fr['State']!r} after "
        f"delete-stack, expected 'cancelled'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
