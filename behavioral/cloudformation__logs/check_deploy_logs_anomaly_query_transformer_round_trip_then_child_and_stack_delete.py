"""deploy-logs-anomaly-query-transformer-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-anomaly-query-transformer-round-trip-then-child-and-stack-delete"
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


def _all_query_definitions(logs, **kw):
    """Every QueryDefinition matching ``kw``: DescribeQueryDefinitions has no botocore paginator."""
    out = []
    next_token = None
    while True:
        resp = logs.describe_query_definitions(**kw, **({"nextToken": next_token} if next_token
                                                         else {}))
        out.extend(resp["queryDefinitions"])
        next_token = resp.get("nextToken")
        if not next_token:
            return out


_EVALUATION_FREQUENCY = "FIVE_MIN"
_QUERY_STRING = "fields @timestamp, @message | limit 20"
_TRANSFORMER_CONFIG = [{"ParseJSON": {}}]


def _own_groups(logs, name):
    return [g for g in paginate(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=name)
            if g["logGroupName"] == name]


def _template(group_name, query_name, with_children=True):
    resources = {
        "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": group_name}},
    }
    outputs = {"GroupRef": {"Value": {"Ref": "LogGroup"}}}
    if with_children:
        resources["Anomaly"] = {"Type": "AWS::Logs::LogAnomalyDetector", "Properties": {
            "LogGroupArnList": [{"Fn::GetAtt": ["LogGroup", "Arn"]}],
            "EvaluationFrequency": _EVALUATION_FREQUENCY,
        }}
        resources["Query"] = {"Type": "AWS::Logs::QueryDefinition", "Properties": {
            "Name": query_name, "QueryString": _QUERY_STRING,
            "LogGroupNames": [{"Ref": "LogGroup"}],
        }}
        resources["Transformer"] = {"Type": "AWS::Logs::Transformer", "Properties": {
            "LogGroupIdentifier": {"Ref": "LogGroup"}, "TransformerConfig": _TRANSFORMER_CONFIG,
        }}
        outputs["AnomalyRef"] = {"Value": {"Ref": "Anomaly"}}
        outputs["AnomalyStatus"] = {"Value": {"Fn::GetAtt": ["Anomaly", "AnomalyDetectorStatus"]}}
        outputs["QueryRef"] = {"Value": {"Ref": "Query"}}
        outputs["TransformerRef"] = {"Value": {"Ref": "Transformer"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation LogAnomalyDetector, QueryDefinition and Transformer read back through
    CloudWatch Logs; an update dropping the children removes each individually, and deleting the
    stack removes the log group too.
    """
    cf = ctx.client("cloudformation")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-cfnlogs-aqt-")
    group = ctx.unique_name("sim2real-cfnlogs-aqt-grp-")
    query_name = ctx.unique_name("sim2real-cfnlogs-aqt-qry-")

    stack_id = create_stack(ctx, cf, stack, _template(group, query_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    groups = _own_groups(logs, group)
    assert [g["logGroupName"] for g in groups] == [out["GroupRef"]] == [group], (
        f"Ref LogGroup {out['GroupRef']!r}, listed {groups!r}"
    )
    # CreateLogAnomalyDetector stores the bare ARN: GetLogAnomalyDetector strips the trailing
    # ":*" that DescribeLogGroups' legacy "arn" field carries.
    group_arn = groups[0]["logGroupArn"]

    # LogAnomalyDetector: found by its log group in the paginated list (never read by the Ref);
    # Ref == that entry's ARN; GetAtt status matches the read; every templated property reads back.
    anomaly_ref = out["AnomalyRef"]
    detectors = [d for d in paginate(logs, "list_log_anomaly_detectors", "anomalyDetectors")
                 if d.get("logGroupArnList") == [group_arn]]
    assert [d["anomalyDetectorArn"] for d in detectors] == [anomaly_ref], (
        f"ListLogAnomalyDetectors on {group_arn!r}: {detectors!r}, Ref {anomaly_ref!r}"
    )
    anomaly = detectors[0]
    assert anomaly["evaluationFrequency"] == _EVALUATION_FREQUENCY, (
        f"evaluationFrequency {anomaly['evaluationFrequency']!r}"
    )
    assert anomaly["anomalyDetectorStatus"] == out["AnomalyStatus"], (
        f"GetAtt AnomalyDetectorStatus {out['AnomalyStatus']!r} != "
        f"read {anomaly['anomalyDetectorStatus']!r}"
    )

    # QueryDefinition: Ref == QueryDefinitionId from an independent read by the declared name.
    query_ref = out["QueryRef"]
    qds = _all_query_definitions(logs, queryDefinitionNamePrefix=query_name)
    qd_matches = [q for q in qds if q["name"] == query_name]
    assert len(qd_matches) == 1, f"describe_query_definitions found {qd_matches!r}"
    qd = qd_matches[0]
    assert qd["queryDefinitionId"] == query_ref, (
        f"Ref QueryDefinition {query_ref!r} != queryDefinitionId {qd['queryDefinitionId']!r}"
    )
    assert qd["queryString"] == _QUERY_STRING, f"queryString {qd['queryString']!r}"
    assert qd["logGroupNames"] == [group], f"logGroupNames {qd['logGroupNames']!r} != [{group!r}]"

    # Transformer: Ref == LogGroupIdentifier echoed back; the processor config reads back.
    transformer_ref = out["TransformerRef"]
    assert transformer_ref == group, f"Ref Transformer {transformer_ref!r} != {group!r}"
    trans = logs.get_transformer(logGroupIdentifier=group)
    assert trans["logGroupIdentifier"] == group, (
        f"GetTransformer logGroupIdentifier {trans['logGroupIdentifier']!r} != {group!r}"
    )
    assert trans["transformerConfig"] == [{"parseJSON": {}}], (
        f"transformerConfig {trans['transformerConfig']!r}"
    )

    # Children before parent: drop Anomaly, Query and Transformer, keep LogGroup; each child's
    # own absence through the owning service while the parent still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(group, query_name,
                                                                with_children=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"

    still_there = _own_groups(logs, group)
    assert [g["logGroupName"] for g in still_there] == [group], (
        f"LogGroup should still answer after the update, got {still_there!r}"
    )
    anomaly_not_found = (
        "ResourceNotFoundException",
        f"The specified ARN does not exist or already deleted : {anomaly_ref}",
    )
    expect_error(
        lambda: logs.get_log_anomaly_detector(anomalyDetectorArn=anomaly_ref), *anomaly_not_found
    )
    qds_after = _all_query_definitions(logs, queryDefinitionNamePrefix=query_name)
    assert qds_after == [], f"QueryDefinition still listed after the update: {qds_after!r}"
    trans_after = logs.get_transformer(logGroupIdentifier=group)["transformerConfig"]
    assert trans_after == [], f"Transformer config still present after the update: {trans_after!r}"

    delete_stack(cf, stack_id)
    gone = _own_groups(logs, group)
    assert gone == [], f"LogGroup still listed after DeleteStack: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
