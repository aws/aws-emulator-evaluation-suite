"""cfn-lambda-alias-out-of-band-repoint-drift."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-lambda-alias-out-of-band-repoint-drift"
GROUP = "drift"
SERVICES = ["cloudformation", "lambda"]

_WAITER_DELAY_S = 2
_WAITER_ATTEMPTS = 90
_DETECT_TIMEOUT_S = 180.0
_DETECT_INTERVAL_S = 2.0
_ALIAS_PROPAGATE_TIMEOUT_S = 60.0
_ALIAS_POLL_INTERVAL_S = 2.0
_ALIAS_NAME = "live"
_HANDLER_SRC = "def handler(event, context):\n    return {'ok': True}\n"


@tags(
    "axis:happy-path",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "cap:c3",
    "cap:c4",
)
def run(ctx) -> None:
    """An alias pointed at a published version detects IN_SYNC, alongside the version.
    Repointed to $LATEST out of band, the alias alone reports MODIFIED with the exact
    expected-vs-actual FunctionVersion difference; the version resource stays IN_SYNC.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    stack_name = ctx.unique_name("sim2real-cfn-aliasdrift-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    template_version = outputs["VerVersion"]
    fn_name = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Fn")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # Beat 1: before any out-of-band change, the whole stack and both resources detect IN_SYNC.
    before = _detect_full(cfn, stack_name)
    assert before["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly created stack must detect as IN_SYNC, got {before['StackDriftStatus']!r}"
    )
    before_drifts = _resource_drift_map(cfn, stack_name)
    assert before_drifts["Ver"]["StackResourceDriftStatus"] == "IN_SYNC", (
        f"Ver drift status before any change: expected IN_SYNC, got {before_drifts['Ver']!r}"
    )
    assert before_drifts["Al"]["StackResourceDriftStatus"] == "IN_SYNC", (
        f"Al drift status before any change: expected IN_SYNC, got {before_drifts['Al']!r}"
    )

    ver_single = cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="Ver")[
        "StackResourceDrift"
    ]
    assert ver_single["StackResourceDriftStatus"] == "IN_SYNC", (
        f"DetectStackResourceDrift on Ver before any change: expected IN_SYNC, got {ver_single!r}"
    )
    al_single = cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="Al")[
        "StackResourceDrift"
    ]
    assert al_single["StackResourceDriftStatus"] == "IN_SYNC", (
        f"DetectStackResourceDrift on Al before any change: expected IN_SYNC, got {al_single!r}"
    )

    # Beat 2: repoint the alias to $LATEST out of band, through Lambda's own API.
    update_resp = lam.update_alias(FunctionName=fn_name, Name=_ALIAS_NAME, FunctionVersion="$LATEST")
    assert update_resp["FunctionVersion"] == "$LATEST", (
        f"UpdateAlias response FunctionVersion: expected '$LATEST', got {update_resp['FunctionVersion']!r}"
    )
    _await_alias_version(lam, fn_name, "$LATEST")

    # Beat 3: the alias now reports MODIFIED, with the exact expected-vs-actual FunctionVersion
    # pair, while the version resource it used to match is untouched and stays IN_SYNC.
    al_after = cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="Al")[
        "StackResourceDrift"
    ]
    assert al_after["StackResourceDriftStatus"] == "MODIFIED", (
        f"Al drift status after the out-of-band repoint: expected MODIFIED, got {al_after!r}"
    )
    fv_diffs = [
        d for d in al_after.get("PropertyDifferences", []) if d["PropertyPath"] == "/FunctionVersion"
    ]
    assert fv_diffs, f"no PropertyDifference for /FunctionVersion: {al_after.get('PropertyDifferences')!r}"
    fv_diff = fv_diffs[0]
    assert fv_diff["DifferenceType"] == "NOT_EQUAL", (
        f"DifferenceType: expected NOT_EQUAL for a changed scalar, got {fv_diff['DifferenceType']!r}"
    )
    assert fv_diff["ExpectedValue"] == template_version, (
        f"ExpectedValue must be the TEMPLATE version {template_version!r}, got {fv_diff['ExpectedValue']!r}"
    )
    assert fv_diff["ActualValue"] == "$LATEST", (
        f"ActualValue must be the LIVE value '$LATEST', got {fv_diff['ActualValue']!r}"
    )

    ver_after = cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="Ver")[
        "StackResourceDrift"
    ]
    assert ver_after["StackResourceDriftStatus"] == "IN_SYNC", (
        f"Ver drift status after the alias-only change: expected IN_SYNC, got {ver_after!r}"
    )

    # Beat 4: the full-stack view agrees: exactly one resource drifted, and it is the alias.
    after = _detect_full(cfn, stack_name)
    assert after["StackDriftStatus"] == "DRIFTED", (
        f"stack drift status after the repoint: expected DRIFTED, got {after['StackDriftStatus']!r}"
    )
    assert after["DriftedStackResourceCount"] == 1, (
        f"exactly one resource drifted, so DriftedStackResourceCount must be 1, got "
        f"{after['DriftedStackResourceCount']!r}"
    )
    after_drifts = _resource_drift_map(cfn, stack_name)
    assert after_drifts["Al"]["StackResourceDriftStatus"] == "MODIFIED", (
        f"Al in the full resource-drift listing: expected MODIFIED, got {after_drifts['Al']!r}"
    )
    assert after_drifts["Ver"]["StackResourceDriftStatus"] == "IN_SYNC", (
        f"Ver in the full resource-drift listing: expected IN_SYNC, got {after_drifts['Ver']!r}"
    )


def _template() -> str:
    """One role, one function, one published version, and one alias pointed at that version."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Code": {"ZipFile": _HANDLER_SRC},
                    },
                },
                "Ver": {
                    "Type": "AWS::Lambda::Version",
                    "Properties": {"FunctionName": {"Ref": "Fn"}},
                },
                "Al": {
                    "Type": "AWS::Lambda::Alias",
                    "Properties": {
                        "FunctionName": {"Ref": "Fn"},
                        "Name": _ALIAS_NAME,
                        "FunctionVersion": {"Fn::GetAtt": ["Ver", "Version"]},
                    },
                },
            },
            "Outputs": {
                "VerVersion": {"Value": {"Fn::GetAtt": ["Ver", "Version"]}},
            },
        }
    )


def _detect_full(cfn, stack_name: str, timeout_s: float = _DETECT_TIMEOUT_S) -> dict:
    """Run a full-stack drift detection to completion and return its status record."""
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if last["DetectionStatus"] in ("DETECTION_COMPLETE", "DETECTION_FAILED"):
            assert last["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {detection_id!r} failed: {last.get('DetectionStatusReason')!r}"
            )
            return last
        time.sleep(_DETECT_INTERVAL_S)
    raise AssertionError(
        f"drift detection {detection_id!r} did not complete within {timeout_s}s (last={last!r})"
    )


def _resource_drift_map(cfn, stack_name: str) -> dict:
    """Every StackResourceDrift the stack's last full detection recorded, keyed by logical id."""
    out: dict = {}
    token = None
    while True:
        kwargs = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kwargs)
        for drift in page["StackResourceDrifts"]:
            out[drift["LogicalResourceId"]] = drift
        token = page.get("NextToken")
        if not token:
            return out


def _await_alias_version(lam, fn_name: str, want: str) -> None:
    """GetAlias can briefly lag UpdateAlias; poll before relying on the new FunctionVersion."""
    deadline = time.monotonic() + _ALIAS_PROPAGATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = lam.get_alias(FunctionName=fn_name, Name=_ALIAS_NAME)["FunctionVersion"]
        if last == want:
            return
        time.sleep(_ALIAS_POLL_INTERVAL_S)
    raise AssertionError(
        f"alias {_ALIAS_NAME!r} FunctionVersion never became {want!r} within "
        f"{_ALIAS_PROPAGATE_TIMEOUT_S}s (last={last!r})"
    )


def _delete_stack_and_wait(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
