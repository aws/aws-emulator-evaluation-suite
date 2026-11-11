"""cfn-deploy-lambda-sesv2-wrong-role-arn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-lambda-sesv2-wrong-role-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack whose function Role names a nonexistent role rolls back and leaves no function (exact
    message), while a sibling stack with a real role deploys a function whose SendEmail reaches
    SES's MessageRejected (exact message)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_role_arn = (
        f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-xsvc-nonexistent-')}"
    )
    stack_name, function_name = _attempt_deploy_with_bogus_role(ctx, bogus_role_arn)

    status = _final_status(ctx, stack_name)
    assert status in {"ROLLBACK_COMPLETE", "CREATE_FAILED"}, f"unexpected stack status: {status}"

    lam = ctx.client("lambda")
    code, message = _error(lambda: lam.get_function(FunctionName=function_name))
    assert code == "ResourceNotFoundException", (
        f"function {function_name} unexpectedly exists after a failed deploy: {code}"
    )
    expected_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{account_id}:function:{function_name}"
    )
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    # Positive control: valid stack-created role in a fresh stack deploys and its function
    # reaches sesv2 (proves the failure above is specific to the bogus role, not a blanket
    # CloudFormation-deploy rejection).
    good_stack = _deploy_cfn(ctx, _valid_template())
    good_function = good_stack["outputs"]["FunctionName"]
    _wait_function_active(ctx, good_function)
    result = _invoke_and_get_result(ctx, good_function)
    assert result["ok"] is False, f"unexpected success payload: {result}"
    assert result["code"] == "MessageRejected", f"unexpected code from control stack: {result}"
    expected_rejection = (
        "Email address is not verified. The following identities failed "
        f"the check in region {ctx.region.upper()}: sim2real-noreply@example.com"
    )
    assert result["message"] == expected_rejection, f"{result!r} != {expected_rejection!r}"


_LAMBDA_CODE = """
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.send_email(
            FromEmailAddress="sim2real-noreply@example.com",
            Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real"},
                    "Body": {"Text": {"Data": "sim2real"}},
                }
            },
        )
        return {"ok": True}
    except ClientError as exc:
        return {
            "ok": False,
            "code": exc.response["Error"]["Code"],
            "message": exc.response["Error"].get("Message", ""),
        }
"""


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _function_resource_with_role(role: Any) -> dict[str, Any]:
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Role": role,
            "Timeout": 15,
            "Code": {"ZipFile": _LAMBDA_CODE},
        },
    }


def _bogus_role_template(role_arn: str) -> str:
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Function": _function_resource_with_role(role_arn)},
        "Outputs": {"FunctionName": {"Value": {"Ref": "Function"}}},
    }
    return json.dumps(doc)


def _valid_role_resource() -> dict[str, Any]:
    return {
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
            },
            "ManagedPolicyArns": [
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            ],
            "Policies": [
                {
                    "PolicyName": "ses-access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": ["ses:SendEmail"], "Resource": "*"}
                        ],
                    },
                }
            ],
        },
    }


def _valid_template() -> str:
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": _valid_role_resource(),
            "Function": _function_resource_with_role({"Fn::GetAtt": ["Role", "Arn"]}),
        },
        "Outputs": {"FunctionName": {"Value": {"Ref": "Function"}}},
    }
    return json.dumps(doc)


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _attempt_deploy_with_bogus_role(ctx, role_arn: str) -> tuple[str, str]:
    """Deploy a stack expected to FAIL (bogus role ARN); register cleanup regardless of
    outcome; return (stack_name, function_name) without asserting CREATE_COMPLETE."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    template_body = _bogus_role_template(role_arn)
    cfn.create_stack(
        StackName=name,
        TemplateBody=template_body,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"CFN stack {name} (expected to fail)",
    )
    # The function logical ID is "Function"; its physical name is auto-generated by CFN and
    # only resolvable through outputs on success, so on failure we derive the same generated
    # name pattern is not available — instead check for stack resource entry.
    try:
        resources = cfn.describe_stack_resources(StackName=name)["StackResources"]
        function_name = next(
            (r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Function" and r.get("PhysicalResourceId")),
            None,
        )
    except ClientError:
        function_name = None
    if function_name is None:
        # No physical resource was ever created; use a name that is guaranteed not to exist.
        function_name = _xname(ctx, "never-created")
    return name, function_name


def _final_status(ctx, stack_name: str) -> str:
    cfn = ctx.client("cloudformation")
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]


def _wait_function_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"function {function_name} Active",
    )


def _invoke_and_get_result(ctx, function_name: str, timeout_s: float = 60.0) -> dict[str, Any]:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
            payload = json.loads(resp["Payload"].read())
            if resp.get("FunctionError"):
                raise AssertionError(f"function {function_name} errored: {payload}")
            return payload
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"invoke of {function_name} never succeeded: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
