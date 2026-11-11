"""cfn-lambda-memory-size-drift-reports-expected-and-actual."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-memory-size-drift-reports-expected-and-actual"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_TEMPLATE_MEMORY = 128
_DRIFTED_MEMORY = 256
_WAITER_DELAY_S = 2
_WAITER_ATTEMPTS = 150
_DETECT_TIMEOUT_S = 180.0
_POLL_INTERVAL_S = 2.0
_PROPAGATE_TIMEOUT_S = 120.0

_HANDLER_SRC = "def handler(event, context):\n    return {'statusCode': 200}\n"


@tags(
    "axis:happy-path",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "cap:c3",
    "cap:c4",
)
def run(ctx) -> None:
    """DetectStackDrift on a stack whose Lambda function MemorySize changed out of band reports
    the stack DRIFTED, and DescribeStackResourceDrifts names /MemorySize with the template and
    live values; deleting the stack removes the function.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    stack_name = ctx.unique_name("sim2real-cfn-lambdadrift-")

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
    created = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert created == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {created!r}"

    fn_name = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Fn")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # Beat 1: positive control — a freshly created stack must detect as IN_SYNC.
    clean = _detect(cfn, stack_name)
    assert clean["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly created stack must detect as IN_SYNC, got {clean['StackDriftStatus']!r} "
        f"({clean.get('DriftedStackResourceCount')!r} drifted)"
    )

    # Beat 2: change exactly one property, out of band, through Lambda's own API.
    lam.update_function_configuration(FunctionName=fn_name, MemorySize=_DRIFTED_MEMORY)
    lam.get_waiter("function_updated_v2").wait(
        FunctionName=fn_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    _await_memory(lam, fn_name, _DRIFTED_MEMORY)

    # Beat 3: drift must name the path, the type, and both values.
    drifted = _detect(cfn, stack_name)
    assert drifted["StackDriftStatus"] == "DRIFTED", (
        f"stack drift status: expected DRIFTED, got {drifted['StackDriftStatus']!r}"
    )
    assert drifted["DriftedStackResourceCount"] == 1, (
        f"exactly one resource drifted, so DriftedStackResourceCount must be 1, got "
        f"{drifted['DriftedStackResourceCount']!r}"
    )
    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(cfn, stack_name)}
    fn_drift = drifts.get("Fn")
    assert fn_drift, f"drift reported nothing for Fn: {sorted(drifts)}"
    assert fn_drift["StackResourceDriftStatus"] == "MODIFIED", (
        f"the out-of-band change must be reported MODIFIED, got "
        f"{fn_drift['StackResourceDriftStatus']!r}"
    )
    diffs = [
        d for d in fn_drift.get("PropertyDifferences", []) if d["PropertyPath"] == "/MemorySize"
    ]
    assert diffs, f"no PropertyDifference for /MemorySize: {fn_drift.get('PropertyDifferences')!r}"
    diff = diffs[0]
    assert diff["DifferenceType"] == "NOT_EQUAL", (
        f"DifferenceType: expected NOT_EQUAL for a changed scalar, got {diff['DifferenceType']!r}"
    )
    assert int(diff["ExpectedValue"]) == _TEMPLATE_MEMORY, (
        f"ExpectedValue must be the TEMPLATE value {_TEMPLATE_MEMORY}, got {diff['ExpectedValue']!r}"
    )
    assert int(diff["ActualValue"]) == _DRIFTED_MEMORY, (
        f"ActualValue must be the LIVE value {_DRIFTED_MEMORY}, got {diff['ActualValue']!r}"
    )

    # Beat 4: delete the stack in band and confirm the function and role are gone through their APIs.
    role_name = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Role")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    code, message = _error_code(lambda: lam.get_function(FunctionName=fn_name))
    want_message = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    assert (code, message) == ("ResourceNotFoundException", want_message), (
        f"expected the function gone with ResourceNotFoundException {want_message!r}, got "
        f"{(code, message)!r}"
    )
    got = _error_code(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the stack's role after the stack delete: {got!r}"
    )


def _template() -> str:
    """One IAM role and one Lambda function, with a hardcoded MemorySize the check will drift."""
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
                        "MemorySize": _TEMPLATE_MEMORY,
                    },
                },
            },
        }
    )


def _error_code(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _await_memory(lam, fn_name: str, want: int) -> None:
    """Lambda's configuration read can lag the update it completed; poll before detecting drift."""
    deadline = time.monotonic() + _PROPAGATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn_name)["MemorySize"]
        if last == want:
            return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"function {fn_name!r} MemorySize never became {want} within {_PROPAGATE_TIMEOUT_S}s "
        f"(last={last!r})"
    )


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


def _resource_drifts(cfn, stack_name: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kw = {"StackName": stack_name}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        out.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            return out


def _delete_stack_and_wait(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
