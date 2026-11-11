"""deploy-logs-loggroup-logstream-metricfilter-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-logs-loggroup-logstream-metricfilter-round-trip-then-child-and-stack-delete"
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


_RETENTION_DAYS = 1
_FILTER_PATTERN = "ERROR"
_METRIC_NAME = "DeployRtErrs"
_METRIC_NAMESPACE = "Sim2RealDeployRt"


def _template(group_name, stream_name, filter_name, with_children=True):
    resources = {
        "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "LogGroupName": group_name, "RetentionInDays": _RETENTION_DAYS,
            "Tags": [{"Key": "sim2real-group", "Value": group_name}],
        }},
    }
    outputs = {
        "GroupRef": {"Value": {"Ref": "LogGroup"}},
        "GroupArn": {"Value": {"Fn::GetAtt": ["LogGroup", "Arn"]}},
    }
    if with_children:
        resources["Stream"] = {"Type": "AWS::Logs::LogStream", "Properties": {
            "LogGroupName": {"Ref": "LogGroup"}, "LogStreamName": stream_name,
        }}
        resources["Filter"] = {"Type": "AWS::Logs::MetricFilter", "Properties": {
            "LogGroupName": {"Ref": "LogGroup"}, "FilterName": filter_name,
            "FilterPattern": _FILTER_PATTERN,
            "MetricTransformations": [{
                "MetricName": _METRIC_NAME, "MetricNamespace": _METRIC_NAMESPACE, "MetricValue": "1",
            }],
        }}
        outputs["StreamRef"] = {"Value": {"Ref": "Stream"}}
        outputs["FilterRef"] = {"Value": {"Ref": "Filter"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LogGroup, LogStream and MetricFilter read back through CloudWatch Logs; an
    update dropping the children removes each individually, and deleting the stack removes the group.
    """
    cf = ctx.client("cloudformation")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-cfnlogs-rt-")
    group = ctx.unique_name("sim2real-cfnlogs-rt-grp-")
    stream = ctx.unique_name("sim2real-cfnlogs-rt-str-")
    filt = ctx.unique_name("sim2real-cfnlogs-rt-flt-")

    stack_id = create_stack(ctx, cf, stack, _template(group, stream, filt))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # LogGroup: Ref against an independent read (ListPrefix by the name we declared), GetAtt
    # against the service's own Arn field, and the one property we set.
    groups = paginate(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=group)
    matches = [g for g in groups if g["logGroupName"] == group]
    assert len(matches) == 1, f"describe_log_groups found {matches!r} for {group!r}"
    lg = matches[0]
    assert lg["arn"] == out["GroupArn"], f"GetAtt Arn {out['GroupArn']!r} != logs arn {lg['arn']!r}"
    assert out["GroupRef"] == lg["logGroupName"], f"Ref LogGroup {out['GroupRef']!r}"
    assert lg["retentionInDays"] == _RETENTION_DAYS, f"retentionInDays {lg['retentionInDays']!r}"
    group_tags = {k: v for k, v in
                  logs.list_tags_for_resource(resourceArn=lg["logGroupArn"])["tags"].items()
                  if not k.startswith("aws:")}
    assert group_tags == {"sim2real": stack, "sim2real-group": group}, f"tags {group_tags!r}"

    # LogStream: Ref against an independent read, scoped to the group we created.
    streams = paginate(
        logs, "describe_log_streams", "logStreams",
        logGroupName=group, logStreamNamePrefix=stream,
    )
    stream_matches = [s for s in streams if s["logStreamName"] == stream]
    assert len(stream_matches) == 1, f"describe_log_streams found {stream_matches!r} for {stream!r}"
    assert out["StreamRef"] == stream_matches[0]["logStreamName"], (
        f"Ref Stream {out['StreamRef']!r}"
    )

    # MetricFilter: Ref against an independent read; every templated property read back.
    filters = paginate(
        logs, "describe_metric_filters", "metricFilters",
        logGroupName=group, filterNamePrefix=filt,
    )
    filter_matches = [f for f in filters if f["filterName"] == filt]
    assert len(filter_matches) == 1, f"describe_metric_filters found {filter_matches!r} for {filt!r}"
    mf = filter_matches[0]
    assert out["FilterRef"] == mf["filterName"], f"Ref Filter {out['FilterRef']!r}"
    assert mf["filterPattern"] == _FILTER_PATTERN, f"filterPattern {mf['filterPattern']!r}"
    assert mf["metricTransformations"] == [{
        "metricName": _METRIC_NAME, "metricNamespace": _METRIC_NAMESPACE, "metricValue": "1",
    }], f"metricTransformations {mf['metricTransformations']!r}"

    # Children before parent: drop Stream and Filter, keep LogGroup; each child's own absence
    # while the parent still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(group, stream, filt,
                                                                with_children=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"

    still_there = paginate(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=group)
    assert [g["logGroupName"] for g in still_there] == [group], (
        f"LogGroup should still answer after the update, got {still_there!r}"
    )
    streams_after = paginate(
        logs, "describe_log_streams", "logStreams",
        logGroupName=group, logStreamNamePrefix=stream,
    )
    assert streams_after == [], f"LogStream still listed after the update: {streams_after!r}"
    filters_after = paginate(
        logs, "describe_metric_filters", "metricFilters",
        logGroupName=group, filterNamePrefix=filt,
    )
    assert filters_after == [], f"MetricFilter still listed after the update: {filters_after!r}"

    delete_stack(cf, stack_id)
    gone = paginate(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=group)
    assert gone == [], f"LogGroup still listed after DeleteStack: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
