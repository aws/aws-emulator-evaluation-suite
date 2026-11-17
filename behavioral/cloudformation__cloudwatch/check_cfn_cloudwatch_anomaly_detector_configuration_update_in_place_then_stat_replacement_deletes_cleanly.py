"""cfn-cloudwatch-anomaly-detector-configuration-update-in-place-then-stat-replacement-deletes-cleanly."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cloudwatch-anomaly-detector-configuration-update-in-place-then-stat-replacement-deletes-cleanly"
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


def _template(namespace: str, metric: str, dim_name: str, dim_value: str, stat: str,
              timezone: str) -> str:
    return json.dumps({
        "Resources": {
            "Detector": {
                "Type": "AWS::CloudWatch::AnomalyDetector",
                "Properties": {
                    "Namespace": namespace,
                    "MetricName": metric,
                    "Stat": stat,
                    "Dimensions": [{"Name": dim_name, "Value": dim_value}],
                    "Configuration": {"MetricTimeZone": timezone},
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


def _rows_since(events: list, seen: set, logical_id: str) -> list:
    """``(status, reason, physical id)`` of events for ``logical_id`` not already in ``seen``."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-managed AWS::CloudWatch::AnomalyDetector updates its Configuration in
    place, replaces itself when its create-only Stat changes, and the stack delete removes the
    replacement detector with no remainder."""
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-cfnad-stack-")
    namespace = ctx.unique_name("Sim2RealCfnAD")
    metric = "ProbeMetric"
    dim_name = "Host"
    dim_value = ctx.unique_name("sim2real-cfnad-host-")

    ctx.on_cleanup(lambda: _delete_stack_named(cf, stack_name))

    # ---- 1. create: Stat Average, MetricTimeZone UTC
    stack_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=_template(namespace, metric, dim_name, dim_value, "Average", "UTC"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "CREATE_COMPLETE")
    first_id = _physical_id(cf, stack_id, "Detector")

    def _assert_created():
        detector = _find_detector(cw, namespace, metric, "Average")
        assert detector is not None, f"no Average detector for {namespace!r}/{metric!r} yet"
        assert detector["Dimensions"] == [{"Name": dim_name, "Value": dim_value}], (
            f"Dimensions {detector['Dimensions']!r}"
        )
        assert detector.get("Configuration", {}).get("MetricTimezone") == "UTC", (
            f"Configuration {detector.get('Configuration')!r}, expected MetricTimeZone 'UTC'"
        )

    _eventually(_assert_created)

    # ---- 2. in-place: a new MetricTimeZone, same detector
    seen = {e["EventId"] for e in _events(cf, stack_id)}
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(namespace, metric, dim_name, dim_value, "Average",
                                "America/New_York"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "UPDATE_COMPLETE")
    rows = _rows_since(_events(cf, stack_id), seen, "Detector")
    statuses = [s for s, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"a Configuration-only change must update in place, got {rows!r}"
    )
    assert _physical_id(cf, stack_id, "Detector") == first_id, (
        f"the in-place update must keep the detector id {first_id!r}"
    )

    def _assert_updated():
        detector = _find_detector(cw, namespace, metric, "Average")
        assert detector is not None, f"the Average detector for {namespace!r}/{metric!r} is gone"
        assert detector.get("Configuration", {}).get("MetricTimezone") == "America/New_York", (
            f"Configuration after the in-place update {detector.get('Configuration')!r}"
        )

    _eventually(_assert_updated)

    # ---- 3. replacement: a new Stat (create-only) replaces the detector with a new one
    seen = {e["EventId"] for e in _events(cf, stack_id)}
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(namespace, metric, dim_name, dim_value, "Maximum",
                                "America/New_York"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "UPDATE_COMPLETE")
    second_id = _physical_id(cf, stack_id, "Detector")
    assert second_id != first_id, "a Stat change must replace the detector with a new physical id"
    rows = _rows_since(_events(cf, stack_id), seen, "Detector")
    deletes = [(status, pid) for status, _, pid in rows
               if status in ("DELETE_COMPLETE", "DELETE_FAILED", "DELETE_SKIPPED")]
    assert deletes == [("DELETE_COMPLETE", first_id)], (
        f"the default UpdateReplacePolicy must delete the replaced detector {first_id!r}, "
        f"got {rows!r}"
    )

    def _assert_replaced():
        assert _find_detector(cw, namespace, metric, "Average") is None, (
            "the replaced Average detector must be gone once the replacement completes"
        )
        detector = _find_detector(cw, namespace, metric, "Maximum")
        assert detector is not None, f"no Maximum detector for {namespace!r}/{metric!r} yet"
        assert detector.get("Configuration", {}).get("MetricTimezone") == "America/New_York", (
            f"Configuration of the replacement {detector.get('Configuration')!r}"
        )

    _eventually(_assert_replaced)

    # ---- 4. delete: no detector and no remainder for this namespace+metric
    cf.delete_stack(StackName=stack_id)
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "DELETE_COMPLETE")

    def _assert_gone():
        assert _find_detector(cw, namespace, metric, "Average") is None, (
            "no detector of this namespace+metric must remain after the stack delete"
        )
        assert _find_detector(cw, namespace, metric, "Maximum") is None, (
            "no detector of this namespace+metric must remain after the stack delete"
        )

    _eventually(_assert_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
