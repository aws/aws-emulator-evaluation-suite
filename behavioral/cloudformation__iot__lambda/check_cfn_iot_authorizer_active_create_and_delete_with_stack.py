"""cfn-iot-authorizer-active-create-and-delete-with-stack."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-authorizer-active-create-and-delete-with-stack"
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
                        "Status": "ACTIVE",
                        "Tags": [{"Key": "team", "Value": "a"}],
                    },
                }
            },
            "Outputs": {
                "AuthRef": {"Value": {"Ref": "Authorizer"}},
                "AuthArn": {"Value": {"Fn::GetAtt": ["Authorizer", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control"
)
def run(ctx) -> None:
    """A CFN AWS::IoT::Authorizer with an explicit AuthorizerName and Status=ACTIVE is created active
    and readable via DescribeAuthorizer, and stack deletion removes it while still ACTIVE, which a
    bare DeleteAuthorizer does not permit without first setting it INACTIVE.
    """
    lam = ctx.client("lambda")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    function_name = ctx.unique_name("sim2real-xsvc-authfn-")
    _create_function(ctx, lam, function_name, _lambda_role(ctx))
    function_arn = lam.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    authorizer_name = ctx.unique_name("sim2real-xsvc-auth-")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(authorizer_name, function_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    stack = _wait_terminal(cfn, stack_name, {"CREATE_COMPLETE"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"create ended in {stack['StackStatus']!r}"
    outputs = _outputs(stack)
    assert outputs["AuthRef"] == authorizer_name, (
        f"expected Ref to be the explicit AuthorizerName {authorizer_name!r}, got {outputs['AuthRef']!r}"
    )

    description = iot.describe_authorizer(authorizerName=authorizer_name)["authorizerDescription"]
    assert description["authorizerArn"] == outputs["AuthArn"], (
        f"GetAtt Arn {outputs['AuthArn']!r} must match DescribeAuthorizer's "
        f"{description['authorizerArn']!r}"
    )
    assert description["status"] == "ACTIVE", f"expected status ACTIVE, got {description['status']!r}"
    assert description["signingDisabled"] is True, (
        f"expected signingDisabled True, got {description['signingDisabled']!r}"
    )
    assert description.get("enableCachingForHttp", False) is False, (
        f"expected enableCachingForHttp False by default, got {description.get('enableCachingForHttp')!r}"
    )
    assert description["authorizerFunctionArn"] == function_arn, (
        f"expected authorizerFunctionArn {function_arn!r}, got {description['authorizerFunctionArn']!r}"
    )
    tag_values = {
        t["Key"]: t["Value"]
        for t in iot.list_tags_for_resource(resourceArn=description["authorizerArn"])["tags"]
    }
    assert tag_values.get("team") == "a", f"expected tag team=a, got {tag_values!r}"

    _delete_stack_and_wait(cfn, stack_name)
    got = _refusal(lambda: iot.describe_authorizer(authorizerName=authorizer_name))
    want = ("ResourceNotFoundException", f"Authorizer {authorizer_name} not found")
    assert got == want, (
        f"after the stack delete of a still-ACTIVE authorizer DescribeAuthorizer must refuse "
        f"{want!r}, got {got!r}"
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


def _refusal(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if not status.endswith("IN_PROGRESS"):
            break
        time.sleep(interval_s)
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
