"""deploy-eventsv2-eventsource-conflicting-configuration-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-eventsv2-eventsource-conflicting-configuration-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "eventbridgev2"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


_AWS_SERVICE_CONFIG = {"AwsServiceEventsConfiguration": {"AwsService": "aws.ec2"}}
_PARTNER_CONFIG = {"PartnerEventsConfiguration": {"PartnerEventSourceArn": {"Fn::Sub": (
    "arn:${AWS::Partition}:events:${AWS::Region}::event-source/aws.partner/example.com/feed/1"
)}}}


def _template(bus_name: str, source_name: str, configuration: dict) -> str:
    """An EventBus and an EventSource; ``configuration`` is the one property under test."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EventBus": {"Type": "AWS::EventsV2::EventBus", "Properties": {"Name": bus_name}},
            "EventSource": {"Type": "AWS::EventsV2::EventSource", "Properties": {
                "Name": source_name, "EventBusArn": {"Ref": "EventBus"},
                "Configuration": configuration}},
        },
        "Outputs": {"EventBusArn": {"Value": {"Ref": "EventBus"}},
                    "EventSourceArn": {"Value": {"Ref": "EventSource"}}},
    })


def _failing_validation_rows(cfn, stack_id: str) -> list:
    """The FAIL validation rows, polled (bounded): they can land just after the terminal status."""
    deadline = time.monotonic() + 60
    while True:
        rows = [r for r in validation_rows(cfn, stack_id) if r[3] == "FAIL"]
        if rows or time.monotonic() > deadline:
            return rows
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EventsV2 EventSource whose Configuration names two variants is refused.

    Early property validation names Configuration and EventBridge v2 lists no bus of the
    template's name, while the same template with one variant deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-cfnebv2bad-bus-")
    source_name = ctx.unique_name("sim2real-behav-cfnebv2bad-src-")

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfnebv2bad-"),
                          _template(bus_name, source_name,
                                    {**_AWS_SERVICE_CONFIG, **_PARTNER_CONFIG}))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    rows = _failing_validation_rows(cfn, bad_id)
    want = [("EventSource", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "#/Configuration: #: 2 subschemas matched instead of one",
             "/Resources/EventSource/Properties/Configuration")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"
    # Nothing reached EventBridge v2: no bus carries the rejected template's name.
    buses = paginate(ebv2, "list_event_buses", "EventBuses", NamePrefix=bus_name)
    assert buses == [], f"a bus named like the rejected template's exists: {buses!r}"

    # Positive control: the same template with only one Configuration variant.
    good_bus = ctx.unique_name("sim2real-behav-cfnebv2good-bus-")
    good_source = ctx.unique_name("sim2real-behav-cfnebv2good-src-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfnebv2good-"),
                           _template(good_bus, good_source, _AWS_SERVICE_CONFIG))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"
    out = stack_outputs(cfn, good_id)
    source = ebv2.describe_event_source(EventSourceArn=out["EventSourceArn"])
    got = (source["Name"], source["EventBusArn"], source["Configuration"])
    assert got == (good_source, out["EventBusArn"], _AWS_SERVICE_CONFIG), (
        f"control event source reads {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
