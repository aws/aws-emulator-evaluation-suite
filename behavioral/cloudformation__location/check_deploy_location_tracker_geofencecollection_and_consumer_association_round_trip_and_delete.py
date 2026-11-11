"""deploy-location-tracker-geofencecollection-and-consumer-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-location-tracker-geofencecollection-and-consumer-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "location"]

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


def _template(tracker_name: str, collection_name: str, tag_value: str, *,
              consumer: bool = True) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Tracker": {
                "Type": "AWS::Location::Tracker",
                "Properties": {"TrackerName": tracker_name, "PositionFiltering": "DistanceBased",
                                "Tags": t},
            },
            "Collection": {
                "Type": "AWS::Location::GeofenceCollection",
                "Properties": {"CollectionName": collection_name, "Tags": t},
            },
            "Consumer": {
                "Type": "AWS::Location::TrackerConsumer",
                "Properties": {"TrackerName": {"Ref": "Tracker"},
                                "ConsumerArn": {"Fn::GetAtt": ["Collection", "Arn"]}},
            },
        },
        "Outputs": {
            "TrackerName": {"Value": {"Ref": "Tracker"}},
            "TrackerArn": {"Value": {"Fn::GetAtt": ["Tracker", "Arn"]}},
            "TrackerCreateTime": {"Value": {"Fn::GetAtt": ["Tracker", "CreateTime"]}},
            "CollectionName": {"Value": {"Ref": "Collection"}},
            "CollectionArn": {"Value": {"Fn::GetAtt": ["Collection", "Arn"]}},
            "CollectionCreateTime": {"Value": {"Fn::GetAtt": ["Collection", "CreateTime"]}},
        },
    }
    if not consumer:
        del template["Resources"]["Consumer"]
    return json.dumps(template)


def _consumers(loc, tracker_name: str) -> list[str]:
    """Every consumer ARN of the tracker, across all ListTrackerConsumers pages."""
    return paginate(loc, "list_tracker_consumers", "ConsumerArns", TrackerName=tracker_name)


def _iso_ms(when) -> str:
    """A timestamp in the GetAtt CreateTime form, YYYY-MM-DDThh:mm:ss.sssZ."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _tags_of(loc, arn: str) -> dict:
    """The resource's tags at Location, without CloudFormation's own aws: system tags."""
    found = loc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {k: v for k, v in found.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Location::Tracker, GeofenceCollection and TrackerConsumer
    association read back through Location with the declared PositionFiltering, tags and
    consumer; dropping the association empties the consumer list, and the delete removes the rest.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-location-trackerconsumer.html
    """
    loc = ctx.client("location")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-locntrkcons-")
    tracker_name = ctx.unique_name("sim2real-loc-trk-")
    collection_name = ctx.unique_name("sim2real-loc-geofc-")

    stack_id = create_stack(ctx, cfn, stack, _template(tracker_name, collection_name, CHECK))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["TrackerName"] == tracker_name, (
        f"expected Ref on the Tracker to equal {tracker_name!r}, stack reports "
        f"{outputs['TrackerName']!r}"
    )
    assert outputs["CollectionName"] == collection_name, (
        f"expected Ref on the Collection to equal {collection_name!r}, stack reports "
        f"{outputs['CollectionName']!r}"
    )

    tracker = loc.describe_tracker(TrackerName=tracker_name)
    assert tracker["TrackerArn"] == outputs["TrackerArn"], (
        f"expected DescribeTracker TrackerArn to equal the stack's GetAtt {outputs['TrackerArn']!r}, "
        f"Location reports {tracker['TrackerArn']!r}"
    )
    assert _iso_ms(tracker["CreateTime"]) == outputs["TrackerCreateTime"], (
        f"expected DescribeTracker CreateTime to equal the stack's GetAtt "
        f"{outputs['TrackerCreateTime']!r}, Location reports {tracker['CreateTime']!r}"
    )
    assert tracker["PositionFiltering"] == "DistanceBased", (
        f"expected the declared PositionFiltering 'DistanceBased', Location reports "
        f"{tracker['PositionFiltering']!r}"
    )

    collection = loc.describe_geofence_collection(CollectionName=collection_name)
    assert collection["CollectionArn"] == outputs["CollectionArn"], (
        f"expected DescribeGeofenceCollection CollectionArn to equal the stack's GetAtt "
        f"{outputs['CollectionArn']!r}, Location reports {collection['CollectionArn']!r}"
    )
    assert _iso_ms(collection["CreateTime"]) == outputs["CollectionCreateTime"], (
        f"expected DescribeGeofenceCollection CreateTime to equal the stack's GetAtt "
        f"{outputs['CollectionCreateTime']!r}, Location reports {collection['CreateTime']!r}"
    )
    for label, arn in (("Tracker", tracker["TrackerArn"]), ("Collection", collection["CollectionArn"])):
        found = _tags_of(loc, arn)
        want_tags = {"sim2real": stack, "sim2real-check": CHECK}
        assert found == want_tags, (
            f"expected the {label}'s stack and declared tags {want_tags!r}, Location reports "
            f"{found!r}"
        )

    consumers = _consumers(loc, tracker_name)
    assert consumers == [outputs["CollectionArn"]], (
        f"expected ListTrackerConsumers({tracker_name!r}) to report exactly "
        f"[{outputs['CollectionArn']!r}], Location reports {consumers!r}"
    )

    # The association's own delete: drop it from the stack while the tracker stays.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(tracker_name, collection_name, CHECK, consumer=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected UPDATE_COMPLETE"
    consumers = _consumers(loc, tracker_name)
    assert consumers == [], (
        f"expected no consumers once the TrackerConsumer is dropped, Location reports {consumers!r}"
    )
    assert loc.describe_tracker(TrackerName=tracker_name)["TrackerName"] == tracker_name, (
        "the tracker should still exist after only its consumer association was dropped"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    tracker_gone = ("ResourceNotFoundException", f"Tracker not found: {tracker_name}.")
    expect_error(lambda: loc.describe_tracker(TrackerName=tracker_name), *tracker_gone)
    collection_gone = ("ResourceNotFoundException",
                       f"Geofence collection not found: {collection_name}.")
    expect_error(lambda: loc.describe_geofence_collection(CollectionName=collection_name),
                 *collection_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
