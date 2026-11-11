"""cfn-logs-delivery-source-destination-and-delivery-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-delivery-source-destination-and-delivery-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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


def _template(src_name, dest_name, dest_group, with_delivery=True):
    resources = {
        "DestLogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": dest_group,
                "RetentionInDays": 1,
                "Tags": [{"Key": "sim2real-dest-group", "Value": dest_group}],
            },
        },
        "DeliveryDest": {
            "Type": "AWS::Logs::DeliveryDestination",
            "Properties": {
                "Name": dest_name,
                "DeliveryDestinationType": "CWL",
                "DestinationResourceArn": {"Fn::GetAtt": ["DestLogGroup", "Arn"]},
                "OutputFormat": "json",
                "Tags": [{"Key": "sim2real-delivery-destination", "Value": dest_name}],
            },
        },
        "DeliverySrc": {
            "Type": "AWS::Logs::DeliverySource",
            "Properties": {
                "Name": src_name,
                "LogType": "INSIGHTS_QUERY_LOGS",
                "ResourceArn": {"Fn::Sub": (
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:*"
                )},
                "Tags": [{"Key": "sim2real-delivery-source", "Value": src_name}],
            },
        },
    }
    outputs = {
        "SourceNameRef": {"Value": {"Ref": "DeliverySrc"}},
        "SourceArn": {"Value": {"Fn::GetAtt": ["DeliverySrc", "Arn"]}},
        "SourceService": {"Value": {"Fn::GetAtt": ["DeliverySrc", "Service"]}},
        "DestNameRef": {"Value": {"Ref": "DeliveryDest"}},
        "DestArn": {"Value": {"Fn::GetAtt": ["DeliveryDest", "Arn"]}},
    }
    if with_delivery:
        resources["Delivery"] = {
            "Type": "AWS::Logs::Delivery",
            "Properties": {
                "DeliverySourceName": {"Ref": "DeliverySrc"},
                "DeliveryDestinationArn": {"Fn::GetAtt": ["DeliveryDest", "Arn"]},
                "Tags": [{"Key": "sim2real-delivery", "Value": src_name}],
            },
            "DependsOn": ["DeliverySrc", "DeliveryDest"],
        }
        outputs.update({
            "DeliveryIdAtt": {"Value": {"Fn::GetAtt": ["Delivery", "DeliveryId"]}},
            "DeliveryArnAtt": {"Value": {"Fn::GetAtt": ["Delivery", "Arn"]}},
            "DeliveryDestTypeAtt": {
                "Value": {"Fn::GetAtt": ["Delivery", "DeliveryDestinationType"]}
            },
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _own_tags(tags_):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {k: v for k, v in tags_.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation delivery source, destination and delivery read back through Logs; an update
    dropping the delivery removes it while source and destination answer, and the stack delete
    removes the rest.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-cfn-dlv-")
    src_name = ctx.unique_name("sim2real-cfn-dlv-src-")
    dest_name = ctx.unique_name("sim2real-cfn-dlv-dst-")
    dest_group = ctx.unique_name("sim2real-cfn-dlv-grp-")

    stack_id = create_stack(ctx, cfn, stack, _template(src_name, dest_name, dest_group))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    insights_arn = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:*"

    # Each Ref against an independent, paginated list (never the Ref used as the lookup key).
    sources = [s for s in paginate(logs, "describe_delivery_sources", "deliverySources")
               if s["name"] == src_name]
    assert len(sources) == 1, f"DescribeDeliverySources lists {len(sources)} for {src_name!r}"
    assert out["SourceNameRef"] == sources[0]["name"], f"Ref {out['SourceNameRef']!r}"
    dests = [d for d in paginate(logs, "describe_delivery_destinations", "deliveryDestinations")
             if d["name"] == dest_name]
    assert len(dests) == 1, f"DescribeDeliveryDestinations lists {len(dests)} for {dest_name!r}"
    assert out["DestNameRef"] == dests[0]["name"], f"Ref {out['DestNameRef']!r}"
    deliveries = [d for d in paginate(logs, "describe_deliveries", "deliveries")
                  if d["deliverySourceName"] == src_name]
    assert len(deliveries) == 1, f"DescribeDeliveries lists {len(deliveries)} for {src_name!r}"
    delivery = deliveries[0]
    assert out["DeliveryIdAtt"] == delivery["id"], f"GetAtt DeliveryId {out['DeliveryIdAtt']!r}"
    groups = [g for g in paginate(logs, "describe_log_groups", "logGroups",
                                  logGroupNamePrefix=dest_group)
              if g["logGroupName"] == dest_group]
    assert len(groups) == 1, f"DescribeLogGroups lists {len(groups)} for {dest_group!r}"
    group = groups[0]
    assert group.get("retentionInDays") == 1, f"retentionInDays {group.get('retentionInDays')!r}"

    # Every templated property and read-only GetAtt against the service's listed entries.
    src = sources[0]
    got = (src["arn"], src["service"], src["logType"], src["resourceArns"])
    assert got == (out["SourceArn"], out["SourceService"], "INSIGHTS_QUERY_LOGS",
                   [insights_arn]), f"delivery source (arn, service, logType, resourceArns) {got!r}"
    dest = dests[0]
    got = (dest["arn"], dest["deliveryDestinationType"], dest["outputFormat"],
           dest["deliveryDestinationConfiguration"]["destinationResourceArn"])
    assert got == (out["DestArn"], "CWL", "json", group["arn"]), (
        f"delivery destination (arn, type, outputFormat, target) {got!r}"
    )
    got = (delivery["arn"], delivery["deliveryDestinationArn"],
           delivery["deliveryDestinationType"])
    assert got == (out["DeliveryArnAtt"], dest["arn"], out["DeliveryDestTypeAtt"]), (
        f"delivery (arn, destination arn, type) {got!r}"
    )
    assert out["DeliveryDestTypeAtt"] == "CWL", f"GetAtt type {out['DeliveryDestTypeAtt']!r}"

    # Template tags plus the propagated stack tag, CloudFormation's aws:* tags dropped.
    for arn, key, value in ((group["logGroupArn"], "sim2real-dest-group", dest_group),
                            (src["arn"], "sim2real-delivery-source", src_name),
                            (dest["arn"], "sim2real-delivery-destination", dest_name),
                            (delivery["arn"], "sim2real-delivery", src_name)):
        got_tags = _own_tags(logs.list_tags_for_resource(resourceArn=arn)["tags"])
        assert got_tags == {"sim2real": stack, key: value}, f"tags of {arn!r}: {got_tags!r}"

    # Child first: an update dropping only the delivery removes it while its source and
    # destination still answer.
    delivery_id = delivery["id"]
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(src_name, dest_name, dest_group, with_delivery=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"delivery-removing update ended {status!r}"
    delivery_gone = ("ResourceNotFoundException",
                     "Requested Delivery does not exist in this account.")
    until_raises(lambda: logs.get_delivery(id=delivery_id))
    expect_error(lambda: logs.get_delivery(id=delivery_id), *delivery_gone)
    kept_src = logs.get_delivery_source(name=src_name)["deliverySource"]["arn"]
    assert kept_src == src["arn"], f"delivery source after dropping the delivery reads {kept_src!r}"
    kept_dest = logs.get_delivery_destination(name=dest_name)["deliveryDestination"]["arn"]
    assert kept_dest == dest["arn"], (
        f"delivery destination after dropping the delivery reads {kept_dest!r}"
    )

    delete_stack(cfn, stack_id)
    dest_gone = ("ResourceNotFoundException",
                 "Requested Delivery Destination does not exist in this account.")
    src_gone = ("ResourceNotFoundException",
                "Requested Delivery Source does not exist in this account.")
    expect_error(lambda: logs.get_delivery_destination(name=dest_name), *dest_gone)
    expect_error(lambda: logs.get_delivery_source(name=src_name), *src_gone)
    remaining = [g for g in paginate(logs, "describe_log_groups", "logGroups",
                                     logGroupNamePrefix=dest_group)
                 if g["logGroupName"] == dest_group]
    assert remaining == [], f"log group {dest_group!r} survived its stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
