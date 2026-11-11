"""deploy-eventschemas-discoverer-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventschemas-discoverer-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "schemas"]

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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_DESCRIPTION = "sim2real discoverer for a CloudFormation provisioning check"


def _template(bus_name, source_arn=None, with_discoverer=True):
    """``source_arn`` overrides the discoverer's SourceArn (default: the stack's bus)."""
    resources = {"Bus": {"Type": "AWS::Events::EventBus", "Properties": {
        "Name": bus_name, "Tags": [{"Key": "sim2real-esch", "Value": bus_name}]}}}
    outputs = {"BusName": {"Value": {"Fn::GetAtt": ["Bus", "Name"]}},
               "BusArn": {"Value": {"Fn::GetAtt": ["Bus", "Arn"]}}}
    if with_discoverer:
        resources["Discoverer"] = {"Type": "AWS::EventSchemas::Discoverer", "Properties": {
            "SourceArn": source_arn or {"Fn::GetAtt": ["Bus", "Arn"]},
            "Description": _DESCRIPTION,
            "CrossAccount": False,
            "Tags": [{"Key": "sim2real-esch", "Value": f"{bus_name}-discoverer"}],
        }}
        outputs.update({
            "DiscovererRef": {"Value": {"Ref": "Discoverer"}},
            "DiscovererArn": {"Value": {"Fn::GetAtt": ["Discoverer", "DiscovererArn"]}},
            "DiscovererId": {"Value": {"Fn::GetAtt": ["Discoverer", "DiscovererId"]}},
            "DiscovererState": {"Value": {"Fn::GetAtt": ["Discoverer", "State"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _discoverers(schemas, source_arn):
    return [(d["DiscovererArn"], d["DiscovererId"]) for d in paginate(
        schemas, "list_discoverers", "Discoverers", SourceArnPrefix=source_arn)
        if d["SourceArn"] == source_arn]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation schema discoverer on a custom event bus reads back STARTED as templated.

    An update dropping the discoverer removes it while the bus remains, and deleting the stack
    removes the bus.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eventschemas-discoverer.html
    """
    cf = ctx.client("cloudformation")
    events = ctx.client("events")
    schemas = ctx.client("schemas")
    stack = ctx.unique_name("sim2real-eschdstack-")
    bus_name = ctx.unique_name("sim2real-eschbus-")

    stack_id = create_stack(ctx, cf, stack, _template(bus_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    bus = events.describe_event_bus(Name=bus_name)
    assert (bus["Name"], bus["Arn"]) == (out["BusName"], out["BusArn"]), f"event bus {bus!r}"

    # Ref and GetAtt against an independent ListDiscoverers by the bus's ARN.
    listed = _discoverers(schemas, out["BusArn"])
    assert listed == [(out["DiscovererRef"], out["DiscovererId"])], (
        f"ListDiscoverers {listed!r}, Ref {out['DiscovererRef']!r}, Id {out['DiscovererId']!r}"
    )
    disc = schemas.describe_discoverer(DiscovererId=listed[0][1])
    have = (disc["DiscovererArn"], disc["SourceArn"], disc["State"], disc["CrossAccount"],
            disc["Description"],
            {k: v for k, v in disc.get("Tags", {}).items() if not k.startswith("aws:")})
    want = (out["DiscovererArn"], out["BusArn"], out["DiscovererState"], False, _DESCRIPTION,
            {"sim2real": stack, "sim2real-esch": f"{bus_name}-discoverer"})
    assert have == want, f"DescribeDiscoverer {have!r}, expected {want!r}"
    assert disc["State"] == "STARTED", f"discoverer State {disc['State']!r}, expected STARTED"

    # The discoverer alone: an update dropping it removes it while the bus still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(bus_name, with_discoverer=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"discoverer-removing update ended {status!r}"
    not_found = ("NotFoundException", f"Discoverer {out['DiscovererId']} does not exist.")
    expect_error(lambda: schemas.describe_discoverer(DiscovererId=out["DiscovererId"]), *not_found)
    assert _discoverers(schemas, out["BusArn"]) == [], "the dropped discoverer is still listed"
    assert events.describe_event_bus(Name=bus_name)["Arn"] == out["BusArn"], "the bus is gone"

    delete_stack(cf, stack_id)
    not_found_2 = ("ResourceNotFoundException", f"Event bus {bus_name} does not exist.")
    expect_error(lambda: events.describe_event_bus(Name=bus_name), *not_found_2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
