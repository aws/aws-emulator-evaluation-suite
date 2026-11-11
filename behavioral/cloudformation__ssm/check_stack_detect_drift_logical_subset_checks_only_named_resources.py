"""stack-detect-drift-logical-subset-checks-only-named-resources."""

from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "stack-detect-drift-logical-subset-checks-only-named-resources"
GROUP = "drift"
SERVICES = ["cloudformation", "ssm"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """With both parameters changed out of band, DetectStackDrift(LogicalResourceIds=[A]) reports
    only A as MODIFIED and leaves B NOT_CHECKED; a full detection then reports both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DetectStackDrift.html"""
    cfn, ssm = ctx.client("cloudformation"), ctx.client("ssm")
    name = ctx.unique_name("sim2real-cfn-subdrift-")
    a, b = ("/" + ctx.unique_name(f"sim2real-cfn-subdrift-{k}-") for k in ("a", "b"))
    stack_id = _create(ctx, cfn, name, _template(a, b))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    for param in (a, b):
        ssm.put_parameter(Name=param, Value="changed", Type="String", Overwrite=True)

    status = _detect(cfn, stack_id, ["A"])
    assert (status["StackDriftStatus"], status["DriftedStackResourceCount"]) == ("DRIFTED", 1), (
        f"subset detection: {status!r}")
    drifts = _drifts(cfn, stack_id)
    assert drifts == {"A": ("MODIFIED", [("/Value", "orig-a", "changed", "NOT_EQUAL")])}, (
        f"subset detection must check A only: {drifts!r}")
    assert (_resource_drift(cfn, stack_id, "A"), _resource_drift(cfn, stack_id, "B")) == ("MODIFIED", "NOT_CHECKED"), (
        f"per-resource drift after the subset detection: {(_resource_drift(cfn, stack_id, 'A'), _resource_drift(cfn, stack_id, 'B'))!r}")

    status = _detect(cfn, stack_id, None)
    assert (status["StackDriftStatus"], status["DriftedStackResourceCount"]) == ("DRIFTED", 2), (
        f"full detection: {status!r}")
    assert _drifts(cfn, stack_id) == {
        "A": ("MODIFIED", [("/Value", "orig-a", "changed", "NOT_EQUAL")]),
        "B": ("MODIFIED", [("/Value", "orig-b", "changed", "NOT_EQUAL")]),
    }, f"full detection: {_drifts(cfn, stack_id)!r}"


def _template(a: str, b: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "A": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": a, "Type": "String", "Value": "orig-a"}},
            "B": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": b, "Type": "String", "Value": "orig-b"}},
        },
    })


def _detect(cfn, stack_id: str, logical_ids: list[str] | None) -> dict:
    """Run a drift detection to DETECTION_COMPLETE and return its status."""
    kwargs = {"StackName": stack_id}
    if logical_ids is not None:
        kwargs["LogicalResourceIds"] = logical_ids
    detection = cfn.detect_stack_drift(**kwargs)["StackDriftDetectionId"]
    status = _poll(lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection),
                   lambda s: s["DetectionStatus"] != "DETECTION_IN_PROGRESS", timeout_s=180.0,
                   what=f"drift detection {detection}")
    assert status["DetectionStatus"] == "DETECTION_COMPLETE", f"drift detection: {status!r}"
    return status


def _drifts(cfn, stack_id: str) -> dict:
    """logical id -> (drift status, sorted property differences) of every reported resource."""
    out: dict = {}
    kwargs = {"StackName": stack_id}
    while True:
        page = cfn.describe_stack_resource_drifts(**kwargs)
        for d in page["StackResourceDrifts"]:
            diffs = sorted((p["PropertyPath"], p["ExpectedValue"], p["ActualValue"], p["DifferenceType"])
                           for p in d.get("PropertyDifferences", []))
            out[d["LogicalResourceId"]] = (d["StackResourceDriftStatus"], diffs)
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _resource_drift(cfn, stack_id: str, logical_id: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)["StackResourceDetail"]
    return detail["DriftInformation"]["StackResourceDriftStatus"]


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
