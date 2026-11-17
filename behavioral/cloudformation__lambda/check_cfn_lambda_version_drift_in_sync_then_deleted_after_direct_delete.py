"""cfn-lambda-version-drift-in-sync-then-deleted-after-direct-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-version-drift-in-sync-then-deleted-after-direct-delete"
GROUP = "drift"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_DETECT_TIMEOUT_S = 180.0
_POLL_INTERVAL_S = 2.0
_SRC = "def handler(event, context):\n    return {'ok': True}\n"


def _template(fn_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": fn_name, "Runtime": "python3.12", "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
            "Ver": {"Type": "AWS::Lambda::Version", "Properties": {"FunctionName": {"Ref": "Fn"}}},
        },
        "Outputs": {
            "VerNumber": {"Value": {"Fn::GetAtt": ["Ver", "Version"]}},
        },
    })


def _poll(probe, predicate, *, timeout_s=_STACK_DEADLINE_S, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


def _delete_stack(cfn, stack: str) -> None:
    status = _stack_status(cfn, stack)
    if status == "GONE":
        return
    if status.endswith("_IN_PROGRESS"):
        _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
              description=f"stack {stack} terminal before delete")
    cfn.delete_stack(StackName=stack)
    final = _poll(lambda: _stack_status(cfn, stack), lambda s: s in ("GONE", "DELETE_FAILED"),
                  description=f"stack {stack} deleted")
    if final != "GONE":
        raise AssertionError(f"stack {stack} did not reach DELETE_COMPLETE, ended {final!r}")


def _detect(cfn, stack_name: str) -> dict:
    """Run one drift detection to completion and return its status record. RAISES on timeout."""
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + _DETECT_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if last["DetectionStatus"] in {"DETECTION_COMPLETE", "DETECTION_FAILED"}:
            assert last["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {detection_id!r} failed: {last.get('DetectionStatusReason')!r}"
            )
            return last
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"drift detection {detection_id!r} did not complete within {_DETECT_TIMEOUT_S}s (last={last!r})"
    )


def _resource_drift(cfn, stack_name: str, logical_id: str) -> dict:
    out = {}
    token = None
    while True:
        kw = {"StackName": stack_name}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        for d in page["StackResourceDrifts"]:
            out[d["LogicalResourceId"]] = d
        token = page.get("NextToken")
        if not token:
            break
    assert logical_id in out, f"no drift entry for {logical_id!r}: {sorted(out)}"
    return out[logical_id]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created stack's AWS::Lambda::Version detects IN_SYNC; once the version is deleted
    directly through Lambda, the next detection reports that resource DELETED, not IN_SYNC.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-cfnlamdrift-")
    stack = ctx.unique_name("sim2real-cfnlamdriftstk-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(fn_name),
                      Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                   description=f"stack {stack} terminal")
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    version = cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"][0]["OutputValue"]

    clean = _detect(cfn, stack)
    assert clean["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly created stack must detect as IN_SYNC, got {clean['StackDriftStatus']!r}"
    )
    clean_drift = _resource_drift(cfn, stack, "Ver")
    assert clean_drift["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the untouched Version resource must report IN_SYNC, got "
        f"{clean_drift['StackResourceDriftStatus']!r}"
    )

    # Delete the published version directly through Lambda, out of band from CloudFormation.
    lam.delete_function(FunctionName=fn_name, Qualifier=version)
    code, message = _error(lambda: lam.get_function_configuration(FunctionName=fn_name, Qualifier=version))
    want_message = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}:{version}"
    assert (code, message) == ("ResourceNotFoundException", want_message), (
        f"expected the deleted version gone with ResourceNotFoundException {want_message!r}, got "
        f"{(code, message)!r}"
    )

    redetected = _detect(cfn, stack)
    assert redetected["StackDriftStatus"] == "DRIFTED", (
        f"a stack with a resource deleted out of band must report DRIFTED, got "
        f"{redetected['StackDriftStatus']!r}"
    )
    deleted_drift = _resource_drift(cfn, stack, "Ver")
    assert deleted_drift["StackResourceDriftStatus"] == "DELETED", (
        f"the Version deleted out of band must report DELETED, got "
        f"{deleted_drift['StackResourceDriftStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
