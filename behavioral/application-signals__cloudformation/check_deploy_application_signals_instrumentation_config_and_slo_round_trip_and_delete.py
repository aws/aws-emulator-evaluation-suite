"""deploy-application-signals-instrumentation-config-and-slo-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-application-signals-instrumentation-config-and-slo-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["application-signals", "cloudformation"]

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

_CODE_LOCATION = {
    "Language": "Python",
    "CodeUnit": "sim2real_handler_mod",
    "MethodName": "handle",
    "FilePath": "app/handler.py",
}
_TAG_KEY = "sim2real-slo"


def _template(service: str, environment: str, slo_name: str, namespace: str, metric: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "InstrumentationConfig": {
                "Type": "AWS::ApplicationSignals::InstrumentationConfig",
                "Properties": {
                    "InstrumentationType": "PROBE",
                    "Service": service,
                    "Environment": environment,
                    "SignalType": "SNAPSHOT",
                    "Location": {"CodeLocation": _CODE_LOCATION},
                    "CaptureConfiguration": {
                        "CodeCapture": {"CaptureLimits": {"MaxHits": 10}}
                    },
                },
            },
            "Slo": {
                "Type": "AWS::ApplicationSignals::ServiceLevelObjective",
                "Properties": {
                    "Name": slo_name,
                    "Sli": {
                        "SliMetric": {
                            "MetricDataQueries": [{
                                "Id": "m1",
                                "MetricStat": {
                                    "Metric": {"Namespace": namespace, "MetricName": metric},
                                    "Period": 60,
                                    "Stat": "Average",
                                },
                                "ReturnData": True,
                            }]
                        },
                        "MetricThreshold": 1,
                        "ComparisonOperator": "LessThanOrEqualTo",
                    },
                    "Goal": {
                        "Interval": {"RollingInterval": {"DurationUnit": "DAY", "Duration": 7}},
                        "AttainmentGoal": 95,
                    },
                    "Tags": [{"Key": _TAG_KEY, "Value": slo_name}],
                },
            },
        },
        "Outputs": {
            "InstrCfgArn": {"Value": {"Fn::GetAtt": ["InstrumentationConfig", "Arn"]}},
            "InstrCfgRef": {"Value": {"Ref": "InstrumentationConfig"}},
            "InstrCfgLocationHash": {
                "Value": {"Fn::GetAtt": ["InstrumentationConfig", "LocationHash"]}},
            "SloArn": {"Value": {"Fn::GetAtt": ["Slo", "Arn"]}},
            "SloRef": {"Value": {"Ref": "Slo"}},
            "SloEvalType": {"Value": {"Fn::GetAtt": ["Slo", "EvaluationType"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation InstrumentationConfig and ServiceLevelObjective read back, then delete.

    Application Signals lists both under their Ref and GetAtts with every templated property and
    the SLO's tag; after the stack delete it refuses each by its id with the exact NotFound.
    """
    appsig = ctx.client("application-signals")
    cfn = ctx.client("cloudformation")
    service = ctx.unique_name("sim2real-appsig-svc-")
    environment = ctx.unique_name("sim2real-appsig-env-")
    slo_name = ctx.unique_name("sim2real-appsig-slo-")
    namespace = ctx.unique_name("sim2real-appsig-ns-")
    metric = ctx.unique_name("sim2real-appsig-metric-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-appsigcfn-"),
                            _template(service, environment, slo_name, namespace, metric))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    location_hash = out["InstrCfgLocationHash"]
    want_ref = f"PROBE|{service}|{environment}|SNAPSHOT|{location_hash}"
    assert out["InstrCfgRef"] == want_ref, f"InstrumentationConfig Ref {out['InstrCfgRef']!r}"

    # InstrumentationConfig: the service's one listed configuration, every templated property.
    listed = paginate(appsig, "list_instrumentation_configurations", "LatestConfigurations",
                      Service=service, Environment=environment, InstrumentationType="PROBE")
    got = [(c["ARN"], c["LocationHash"], c["SignalType"], c["Location"], c["CaptureConfiguration"])
           for c in listed]
    want = [(out["InstrCfgArn"], location_hash, "SNAPSHOT", {"CodeLocation": _CODE_LOCATION},
             {"CodeCapture": {"CaptureLimits": {"MaxHits": 10}}})]
    assert got == want, f"instrumentation configurations {got!r}, expected {want!r}"

    # SLO: Ref against the SLO listed under its name; every templated property and the tag.
    arns = [s["Arn"] for s in paginate(appsig, "list_service_level_objectives", "SloSummaries")
            if s["Name"] == slo_name]
    assert arns == [out["SloRef"]] and out["SloRef"] == out["SloArn"], (
        f"SLOs named {slo_name!r}: {arns!r}, Ref {out['SloRef']!r}, Arn {out['SloArn']!r}"
    )
    slo = appsig.get_service_level_objective(Id=out["SloArn"])["Slo"]
    query = slo["Sli"]["SliMetric"]["MetricDataQueries"]
    got = (slo["Name"], slo["EvaluationType"], slo["Sli"]["MetricThreshold"],
           slo["Sli"]["ComparisonOperator"], slo["Goal"]["Interval"], slo["Goal"]["AttainmentGoal"],
           [(q["Id"], q["MetricStat"]["Metric"]["Namespace"], q["MetricStat"]["Metric"]["MetricName"],
             q["MetricStat"]["Period"], q["MetricStat"]["Stat"], q["ReturnData"]) for q in query])
    want = (slo_name, out["SloEvalType"], 1.0, "LessThanOrEqualTo",
            {"RollingInterval": {"DurationUnit": "DAY", "Duration": 7}}, 95.0,
            [("m1", namespace, metric, 60, "Average", True)])
    assert got == want, f"SLO reads {got!r}, expected {want!r}"
    slo_tags = {t["Key"]: t["Value"] for t in appsig.list_tags_for_resource(
        ResourceArn=out["SloArn"])["Tags"] if t["Key"] == _TAG_KEY}
    assert slo_tags == {_TAG_KEY: slo_name}, f"SLO tags {slo_tags!r}"

    delete_stack(cfn, stack_id)
    refused = ("ResourceNotFoundException", "The requested instrumentation configuration has been deleted.")
    expect_error(lambda: appsig.get_instrumentation_configuration(
        Service=service, Environment=environment, SignalType="SNAPSHOT",
        InstrumentationType="PROBE", LocationIdentifier={"LocationHash": location_hash},
    ), *refused)
    refused = ("ResourceNotFoundException", f"Slo with arn '{out['SloArn']}' does not exist.")
    expect_error(lambda: appsig.get_service_level_objective(Id=out["SloArn"]), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
