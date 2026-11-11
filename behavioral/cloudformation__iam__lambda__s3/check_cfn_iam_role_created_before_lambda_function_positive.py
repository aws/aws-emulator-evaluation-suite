"""cfn-iam-role-created-before-lambda-function-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-created-before-lambda-function-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """The IAM role reaches CREATE_COMPLETE before the dependent Lambda function's creation even
    starts (the implicit DependsOn CloudFormation infers from Fn::GetAtt), and the deployed
    function is actually invocable using that role."""
    function_name = _xname(ctx, "fn")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
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
                    },
                },
                "Function": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": function_name,
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 10,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {
                            "ZipFile": "def handler(event, context):\n    return {'ok': True}\n"
                        },
                    },
                },
            },
        }
    )

    result = _deploy_cfn(ctx, template, capabilities=["CAPABILITY_IAM"])
    cfn = ctx.client("cloudformation")

    events = cfn.describe_stack_events(StackName=result["stack_name"])["StackEvents"]

    def _timestamp(logical_id: str, status: str):
        matches = [
            e["Timestamp"]
            for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
        ]
        if not matches:
            raise AssertionError(f"no {status} event found for {logical_id}")
        return min(matches)

    role_complete = _timestamp("ExecRole", "CREATE_COMPLETE")
    function_start = _timestamp("Function", "CREATE_IN_PROGRESS")
    assert role_complete <= function_start, (
        f"role completed at {role_complete} but function creation started earlier at "
        f"{function_start}"
    )

    _wait_lambda_active(ctx, function_name)
    _, body = _invoke_lambda(ctx, function_name)
    assert body == {"ok": True}, f"invoking {function_name} with the deployed role returned {body!r}, expected {{'ok': True}}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


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
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
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


def _wait_lambda_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"lambda {function_name} Active",
    )


def _invoke_lambda(ctx, function_name: str, payload: dict | None = None):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    assert "FunctionError" not in resp, resp.get("FunctionError")
    body = json.loads(resp["Payload"].read())
    return resp, body


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
