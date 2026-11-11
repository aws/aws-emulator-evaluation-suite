"""deploy-gamelift-fleet-anywhere-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-gamelift-fleet-anywhere-round-trip-and-delete"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "gamelift"]

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


# ---- Check-specific: the template, then run(). ----

def _template(location_name: str, fleet_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Location": {
                "Type": "AWS::GameLift::Location",
                "Properties": {"LocationName": location_name},
            },
            "Fleet": {
                "Type": "AWS::GameLift::Fleet",
                "Properties": {
                    "Name": fleet_name,
                    "ComputeType": "ANYWHERE",
                    "Locations": [{"Location": location_name}],
                },
                "DependsOn": "Location",
            },
        },
        "Outputs": {
            "FleetId": {"Value": {"Ref": "Fleet"}},
            "FleetArn": {"Value": {"Fn::GetAtt": ["Fleet", "FleetArn"]}},
            "LocationName": {"Value": {"Ref": "Location"}},
            "LocationArn": {"Value": {"Fn::GetAtt": ["Location", "LocationArn"]}},
        },
    })


def _custom_locations(gl) -> dict[str, str]:
    """Every custom location's name -> ARN, read across all pages of ListLocations."""
    found: dict[str, str] = {}
    kwargs: dict = {"Filters": ["CUSTOM"]}
    while True:
        page = gl.list_locations(**kwargs)
        for loc in page.get("Locations", []):
            found[loc["LocationName"]] = loc["LocationArn"]
        if not page.get("NextToken"):
            return found
        kwargs["NextToken"] = page["NextToken"]


def _fleet_ids_named(gl, name: str) -> list[str]:
    """The FleetId of every fleet called ``name``, read across all pages of DescribeFleetAttributes."""
    ids: list[str] = []
    kwargs: dict = {}
    while True:
        page = gl.describe_fleet_attributes(**kwargs)
        ids += [f["FleetId"] for f in page.get("FleetAttributes", []) if f.get("Name") == name]
        if not page.get("NextToken"):
            return ids
        kwargs["NextToken"] = page["NextToken"]


def _wait_fleet_active(gl, fleet_id: str, deadline_s: float = 240.0, poll_s: float = 3.0) -> dict:
    """Poll DescribeFleetAttributes until the fleet leaves a transitional status."""
    deadline = time.monotonic() + deadline_s
    transitional = {"NEW", "DOWNLOADING", "VALIDATING", "BUILDING", "ACTIVATING"}
    while True:
        fleet = gl.describe_fleet_attributes(FleetIds=[fleet_id])["FleetAttributes"][0]
        if fleet["Status"] not in transitional:
            return fleet
        assert time.monotonic() < deadline, (
            f"fleet {fleet_id!r} still {fleet['Status']!r} after {deadline_s}s"
        )
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ANYWHERE AWS::GameLift::Fleet and its AWS::GameLift::Location reach GameLift
    with the declared Name, ComputeType, location and ARNs, and deleting the stack removes both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gamelift-fleet.html
    """
    gl = ctx.client("gamelift")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-glfleet-")
    location_name = "custom-" + ctx.unique_name("sim2real-glfleet-loc-")
    fleet_name = ctx.unique_name("sim2real-glfleet-name-")

    stack_id = create_stack(ctx, cfn, stack, _template(location_name, fleet_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    fleet_id, fleet_arn = outputs["FleetId"], outputs["FleetArn"]

    named = _fleet_ids_named(gl, fleet_name)
    assert named == [fleet_id], (
        f"expected Ref Fleet to be the one FleetId GameLift lists for {fleet_name!r}, "
        f"Ref gave {fleet_id!r} and GameLift lists {named!r}"
    )
    custom = _custom_locations(gl)
    assert outputs["LocationName"] == location_name, (
        f"expected Ref Location {location_name!r}, got {outputs['LocationName']!r}"
    )
    assert custom.get(location_name) == outputs["LocationArn"], (
        f"expected ListLocations to carry {location_name!r} with the GetAtt LocationArn, "
        f"GameLift reports {custom.get(location_name)!r}"
    )

    fleet = _wait_fleet_active(gl, fleet_id)
    assert fleet["Status"] == "ACTIVE", f"expected fleet Status ACTIVE, GameLift reports {fleet['Status']!r}"
    assert fleet["FleetArn"] == fleet_arn, f"expected FleetArn {fleet_arn!r}, GameLift reports {fleet['FleetArn']!r}"
    assert fleet["Name"] == fleet_name, f"expected Name {fleet_name!r}, GameLift reports {fleet['Name']!r}"
    assert fleet["ComputeType"] == "ANYWHERE", (
        f"expected ComputeType ANYWHERE, GameLift reports {fleet['ComputeType']!r}"
    )

    locations = gl.describe_fleet_location_attributes(FleetId=fleet_id)["LocationAttributes"]
    location_names = [loc["LocationState"]["Location"] for loc in locations]
    assert location_names == [location_name], (
        f"expected the fleet's one location to be {location_name!r}, GameLift reports {location_names!r}"
    )

    delete_stack(cfn, stack_id)

    # A deleted fleet has no tombstone: it drops out of DescribeFleetAttributes entirely rather
    # than erroring, so the absence read must use the same accepted FleetId.
    after = gl.describe_fleet_attributes(FleetIds=[fleet_id])["FleetAttributes"]
    assert after == [], f"expected the deleted fleet to be gone, GameLift still reports {after!r}"
    left = _custom_locations(gl)
    assert location_name not in left, (
        f"expected the deleted custom location {location_name!r} gone from ListLocations, "
        f"GameLift still reports it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
