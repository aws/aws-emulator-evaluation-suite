"""cfn-iot-authorizer-duplicate-name-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-authorizer-duplicate-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot", "lambda"]

_LAMBDA_CODE = (
    "def handler(event, context):\n"
    "    return {'isAuthenticated': True, 'principalId': 'sim2real', 'disconnectAfterInSeconds': 3600,"
    " 'refreshAfterInSeconds': 3600, 'policyDocuments': []}\n"
)


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _template(authorizer_name: str, function_arn: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Authorizer": {
                    "Type": "AWS::IoT::Authorizer",
                    "Properties": {
                        "AuthorizerName": authorizer_name,
                        "AuthorizerFunctionArn": function_arn,
                        "SigningDisabled": True,
                    },
                }
            },
            "Outputs": {"AuthRef": {"Value": {"Ref": "Authorizer"}}},
        }
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring an AWS::IoT::Authorizer with an existing AuthorizerName fails early
    validation with a name-conflict event on that resource and leaves the pre-existing authorizer
    unchanged; the same template under a fresh name creates."""
    lam = ctx.client("lambda")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    function_name = ctx.unique_name("sim2real-xsvc-authfn-")
    _create_function(ctx, lam, function_name, _lambda_role(ctx))
    function_arn = lam.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    existing_name = ctx.unique_name("sim2real-xsvc-auth-")
    iot.create_authorizer(
        authorizerName=existing_name, authorizerFunctionArn=function_arn, signingDisabled=True
    )
    ctx.on_cleanup(lambda: _deactivate_and_delete(iot, existing_name))
    before = iot.describe_authorizer(authorizerName=existing_name)["authorizerDescription"]

    conflict_stack = ctx.unique_name("sim2real-xsvc-stk-")
    conflict_id = cfn.create_stack(
        StackName=conflict_stack,
        TemplateBody=_template(existing_name, function_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, conflict_id))
    stack = _wait_terminal(cfn, conflict_stack, {"ROLLBACK_COMPLETE", "CREATE_FAILED"})
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected the conflicting create to roll back, got {stack['StackStatus']!r}"
    )
    reason = _resource_status_reason(cfn, conflict_stack, conflict_stack, "CREATE_FAILED")
    expected_reason = (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
        "with resource and property details, resolve each error, then retry the operation."
    )
    assert reason == expected_reason, (
        f"expected the stack's CREATE_FAILED reason {expected_reason!r}, got {reason!r}"
    )
    # The one validation failure the reason points at names the authorizer and the duplicate name.
    failures = _validation_failures(cfn, conflict_id)
    expected_failure = {
        "LogicalResourceId": "Authorizer",
        "ResourceType": "AWS::IoT::Authorizer",
        "ValidationStatus": "FAILED",
        "ValidationStatusReason": (
            f"Resource of type 'AWS::IoT::Authorizer' with identifier '{existing_name}' already "
            f"exists."
        ),
    }
    assert failures == [expected_failure], (
        f"DescribeEvents for {conflict_stack!r} lists validation failures {failures!r}, expected "
        f"exactly [{expected_failure!r}]"
    )
    resources = cfn.list_stack_resources(StackName=conflict_stack)["StackResourceSummaries"]
    assert resources == [], (
        "a name-conflict caught by CFN's own pre-create validation must never reach the "
        f"resource handler, but the stack has resources {resources!r}"
    )

    after = iot.describe_authorizer(authorizerName=existing_name)["authorizerDescription"]
    assert after["authorizerArn"] == before["authorizerArn"], (
        "the pre-existing authorizer must be untouched by the rejected create, "
        f"arn changed from {before['authorizerArn']!r} to {after['authorizerArn']!r}"
    )
    assert after["status"] == before["status"], (
        f"the pre-existing authorizer's status must be untouched, {before['status']!r} -> {after['status']!r}"
    )

    # Positive control: the identical template under a fresh name creates cleanly.
    fresh_name = ctx.unique_name("sim2real-xsvc-auth-")
    control_stack = ctx.unique_name("sim2real-xsvc-stk-")
    control_id = cfn.create_stack(
        StackName=control_stack,
        TemplateBody=_template(fresh_name, function_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, control_id))
    stack = _wait_terminal(cfn, control_stack, {"CREATE_COMPLETE"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the positive control under a fresh name must create cleanly, got {stack['StackStatus']!r}"
    )
    control = iot.describe_authorizer(authorizerName=fresh_name)["authorizerDescription"]
    assert control["authorizerFunctionArn"] == function_arn, (
        f"expected the control authorizer's function ARN {function_arn!r}, got "
        f"{control['authorizerFunctionArn']!r}"
    )


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _lambda_role(ctx) -> str:
    """The authorizer function's execution role, created by this check. The function is never
    invoked, so the role carries no permission beyond the Lambda trust."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-authfn-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_function(ctx, lam, name: str, role_arn: str) -> None:
    """CreateFunction, retrying only the refusal Lambda returns while a new role propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_bytes(_LAMBDA_CODE)}, Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] != "InvalidParameterValueException"
                    or "cannot be assumed" not in err.get("Message", "")
                    or time.monotonic() > deadline):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))


def _deactivate_and_delete(iot, name: str) -> None:
    """IoT refuses DeleteAuthorizer on an ACTIVE authorizer, so flip it INACTIVE first."""
    iot.update_authorizer(authorizerName=name, status="INACTIVE")
    iot.delete_authorizer(authorizerName=name)


def _validation_failures(cfn, stack_id: str) -> list[dict[str, Any]]:
    """The stack's failed validation events from DescribeEvents, reduced to the graded fields."""
    keys = ("LogicalResourceId", "ResourceType", "ValidationStatus", "ValidationStatusReason")
    found: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_id}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_events(**kwargs)
        for event in page["OperationEvents"]:
            if event.get("ValidationStatus") == "FAILED":
                found.append({k: event.get(k) for k in keys})
        token = page.get("NextToken")
        if not token:
            return found


def _resource_status_reason(cfn, stack_name: str, logical_id: str, status: str) -> str | None:
    for event in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]:
        if event.get("LogicalResourceId") == logical_id and event.get("ResourceStatus") == status:
            return event.get("ResourceStatusReason")
    return None


def _wait_terminal(cfn, stack_name: str, ok_statuses, timeout_s: float = 300.0, interval_s: float = 5.0):
    terminal_fallback = {
        "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last = stacks[0]
        if last["StackStatus"] in ok_statuses or last["StackStatus"] in terminal_fallback:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
