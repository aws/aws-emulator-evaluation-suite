"""cfn-cloudwatch-anomaly-detector-update-to-invalid-stat-rolls-back-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cloudwatch-anomaly-detector-update-to-invalid-stat-rolls-back-unchanged"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

_STACK_CAP_S = 300.0
_READ_CAP_S = 60.0
_POLL_S = 2.0

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _template(namespace: str, metric: str, dim_name: str, dim_value: str, stat: str) -> str:
    return json.dumps({
        "Resources": {
            "Detector": {
                "Type": "AWS::CloudWatch::AnomalyDetector",
                "Properties": {
                    "Namespace": namespace,
                    "MetricName": metric,
                    "Stat": stat,
                    "Dimensions": [{"Name": dim_name, "Value": dim_value}],
                },
            },
        },
        "Outputs": {"DetectorRef": {"Value": {"Ref": "Detector"}}},
    })


def _settle(cf, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until a terminal status; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cf, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    events = _events(cf, stack["StackId"])
    failed = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
              for e in events if e["ResourceStatus"].endswith("_FAILED")]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r}, expected {want!r}; failed resources: {failed!r}"
    )


def _events(cf, stack_id: str) -> list:
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        rows.extend(page["StackEvents"])
    return list(reversed(rows))


def _physical_id(cf, stack_id: str, logical_id: str) -> str:
    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id}")


def _find_detector(cw, namespace: str, metric: str, stat: str) -> dict | None:
    detectors = []
    for page in cw.get_paginator("describe_anomaly_detectors").paginate(
            Namespace=namespace, MetricName=metric):
        detectors.extend(page["AnomalyDetectors"])
    matches = [d for d in detectors if d["Stat"] == stat]
    assert len(matches) <= 1, f"expected at most one detector of Stat {stat!r}, got {matches!r}"
    return matches[0] if matches else None


def _eventually(fn, timeout_s: float = _READ_CAP_S):
    """Run ``fn()`` (an assert) until it stops raising; raise its last failure past the budget."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except AssertionError:
            if time.monotonic() > deadline:
                raise
            time.sleep(_POLL_S)


def _delete_stack_named(cf, name: str) -> None:
    try:
        stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
                "ValidationError", f"Stack with id {name} does not exist"):
            return
        raise
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(cf, stack_id)
    cf.delete_stack(StackName=stack_id)
    stack = _settle(cf, stack_id)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(f"teardown: stack {name} ended {stack['StackStatus']!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation update that replaces AWS::CloudWatch::AnomalyDetector's create-only Stat
    with a value PutAnomalyDetector refuses rolls the stack back, leaving the original detector
    untouched.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-cfnadr-stack-")
    namespace = ctx.unique_name("Sim2RealCfnADR")
    metric = "ProbeMetric"
    dim_name = "Host"
    dim_value = ctx.unique_name("sim2real-cfnadr-host-")

    ctx.on_cleanup(lambda: _delete_stack_named(cf, stack_name))

    # ---- positive control: the detector deploys with a valid Stat
    stack_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=_template(namespace, metric, dim_name, dim_value, "Average"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "CREATE_COMPLETE")
    first_id = _physical_id(cf, stack_id, "Detector")
    _eventually(lambda: _assert_exists(cw, namespace, metric, "Average"))

    # ---- break exactly one thing: a Stat PutAnomalyDetector does not accept
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(namespace, metric, dim_name, dim_value, "NotAValidStat"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update to an invalid Stat must roll back, got {stack['StackStatus']!r}: "
        f"{_events(cf, stack_id)!r}"
    )
    events = _events(cf, stack_id)
    failed = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events
              if e["LogicalResourceId"] == "Detector" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert failed, f"expected a Detector UPDATE_FAILED event, stack events were {events!r}"

    # ---- effect absent: the original detector's physical id and Stat are unchanged
    assert _physical_id(cf, stack_id, "Detector") == first_id, (
        "a rolled-back update must leave the detector's physical id unchanged"
    )
    assert _find_detector(cw, namespace, metric, "NotAValidStat") is None, (
        "no detector of the refused Stat must have been created"
    )
    _eventually(lambda: _assert_exists(cw, namespace, metric, "Average"))

    # ---- restore: an identical call (the positive control's shape) succeeds again
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(namespace, metric, dim_name, dim_value, "Average"),
        Tags=[{"Key": "sim2real", "Value": stack_name}, {"Key": "retry", "Value": "1"}],
    )
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "UPDATE_COMPLETE")
    _eventually(lambda: _assert_exists(cw, namespace, metric, "Average"))


def _assert_exists(cw, namespace: str, metric: str, stat: str) -> None:
    detector = _find_detector(cw, namespace, metric, stat)
    assert detector is not None, f"no {stat} detector for {namespace!r}/{metric!r} yet"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
