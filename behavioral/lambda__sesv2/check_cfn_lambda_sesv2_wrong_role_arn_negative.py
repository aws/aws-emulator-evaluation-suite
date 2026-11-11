"""cfn-lambda-sesv2-wrong-role-arn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-sesv2-wrong-role-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose function Role names a nonexistent role fails to deploy and leaves no function
    (exact message), while an otherwise identical stack with a real role deploys the function."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_role_name = _xname(ctx, "no-such-role")
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{bogus_role_name}"
    bad_function_name = _xname(ctx, "fn-badrole")
    bad_stack_name = _xname(ctx, "stk-badrole")

    bad_template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": bad_function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": bogus_role_arn,
                    "Timeout": 30,
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
        },
    })

    status = _create_stack_allow_failure(ctx, bad_template, bad_stack_name)
    assert status in {"ROLLBACK_COMPLETE", "CREATE_FAILED"}, f"unexpected terminal status: {status}"

    lam = ctx.client("lambda")
    code, message = _error(lambda: lam.get_function(FunctionName=bad_function_name))
    assert code == "ResourceNotFoundException", (
        "the function must never have come into existence — that is the proof no sesv2 call "
        f"could ever have been made from it (got code={code!r})"
    )
    expected_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{account_id}:function:{bad_function_name}"
    )
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    # Positive control: an otherwise-identical stack, but with a real role ARN, deploys fine.
    good_role_name = _xname(ctx, "role-ok")
    good_function_name = _xname(ctx, "fn-ok")
    good_template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": good_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": good_function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
        },
        "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
    })
    good_result = _deploy_cfn(ctx, good_template)
    assert good_result["outputs"]["FunctionName"] == good_function_name, (
        f"stack output FunctionName mismatch: expected {good_function_name!r}, "
        f"got {good_result['outputs'].get('FunctionName')!r}"
    )
    good_fn = lam.get_function(FunctionName=good_function_name)
    assert good_fn["Configuration"]["FunctionName"] == good_function_name, (
        "independent get_function read disagrees with the stack output: expected "
        f"{good_function_name!r}, got {good_fn['Configuration'].get('FunctionName')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER_CODE = """
import json
import os

import boto3


def handler(event, context):
    client = boto3.client("sesv2")
    kwargs = {
        "FromEmailAddress": event["from"],
        "Destination": {"ToAddresses": [event["to"]]},
        "Content": {
            "Simple": {
                "Subject": {"Data": "sim2real test"},
                "Body": {"Text": {"Data": "hello from lambda"}},
            }
        },
    }
    config_set = os.environ.get("CONFIG_SET")
    if config_set:
        kwargs["ConfigurationSetName"] = config_set
    try:
        resp = client.send_email(**kwargs)
        return {"ok": True, "messageId": resp["MessageId"]}
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        return {"ok": False, "error": type(exc).__name__, "code": code}
""".strip()


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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


def _create_stack_allow_failure(ctx, template: str, stack_name: str) -> str:
    """Like _deploy_cfn, but TOLERATES (and returns) a failure terminal status instead of raising —
    for negative checks whose whole point is that the stack fails to create. Still registers the
    delete-and-wait teardown so a ROLLBACK_COMPLETE stack (which CloudFormation keeps around) is
    cleaned up."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"CFN stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
