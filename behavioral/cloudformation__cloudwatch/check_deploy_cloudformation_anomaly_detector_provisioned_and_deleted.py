"""deploy-cloudformation-anomaly-detector-provisioned-and-deleted."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cloudformation-anomaly-detector-provisioned-and-deleted"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

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


# ---- Check-specific: the template, then run(). ----

def _find_detector(cw, namespace: str, metric_name: str) -> dict | None:
    detectors = paginate(cw, "describe_anomaly_detectors", "AnomalyDetectors",
                         Namespace=namespace, MetricName=metric_name)
    assert len(detectors) <= 1, f"expected at most one detector for this namespace+metric, got {detectors!r}"
    return detectors[0] if detectors else None


@tags(
    "axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CFN-deployed AWS::CloudWatch::AnomalyDetector really exists in CloudWatch with the
    template's stat and dimension, its Ref is a CloudFormation-minted physical id, and stack
    deletion removes it.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAnomalyDetectors.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-behav-adstk-")
    namespace = ctx.unique_name("Sim2RealBehavAD")
    metric_name = "ProbeMetric"
    dimension_name = "Host"
    dimension_value = ctx.unique_name("sim2real-behav-host-")

    template = {
        "Resources": {
            "Detector": {
                "Type": "AWS::CloudWatch::AnomalyDetector",
                "Properties": {
                    "Namespace": namespace,
                    "MetricName": metric_name,
                    "Stat": "Average",
                    "Dimensions": [{"Name": dimension_name, "Value": dimension_value}],
                },
            },
        },
        "Outputs": {"DetectorRef": {"Value": {"Ref": "Detector"}}},
    }

    stack_id = create_stack(ctx, cf, stack_name, json.dumps(template))
    status = wait_stack(cf, stack_id, timeout_s=240.0)
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    physical_id = cf.describe_stack_resources(
        StackName=stack_id, LogicalResourceId="Detector",
    )["StackResources"][0]["PhysicalResourceId"]
    assert outputs["DetectorRef"] == physical_id, (
        f"Ref should equal the resource's PhysicalResourceId {physical_id!r}, "
        f"got {outputs['DetectorRef']!r}"
    )
    assert re.fullmatch(r"Detector-[A-Za-z0-9]{12}", outputs["DetectorRef"]), (
        f"Ref should be a Detector-<12-character suffix> physical id, got "
        f"{outputs['DetectorRef']!r}"
    )

    detector = _find_detector(cw, namespace, metric_name)
    assert detector is not None, (
        f"stack claims CREATE_COMPLETE but no anomaly detector exists for namespace "
        f"{namespace!r}, metric {metric_name!r}"
    )
    got = (detector["Namespace"], detector["MetricName"], detector["Stat"])
    assert got == (namespace, metric_name, "Average"), (
        f"expected the template's namespace, metric and stat, got {got!r}"
    )
    assert detector["Dimensions"] == [{"Name": dimension_name, "Value": dimension_value}], (
        f"expected the template's dimension, got {detector['Dimensions']!r}"
    )

    delete_stack(cf, stack_id)

    remaining = _find_detector(cw, namespace, metric_name)
    assert remaining is None, (
        f"anomaly detector for namespace {namespace!r}, metric {metric_name!r} is still "
        f"present after stack deletion: {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
