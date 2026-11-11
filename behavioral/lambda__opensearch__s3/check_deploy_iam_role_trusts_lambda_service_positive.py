"""deploy-iam-role-trusts-lambda-service-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-role-trusts-lambda-service-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "opensearch", "s3"]

_LAMBDA_CODE = """
import boto3


def handler(event, context):
    identity = boto3.client("sts").get_caller_identity()
    return {"arn": identity["Arn"], "doubled": event.get("n", 0) * 2}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed IAM role that trusts lambda.amazonaws.com lets a Lambda function
    actually ASSUME that role at invocation time (not merely deploy without error)."""
    role_name = _xname(ctx, "role")
    function_name = _xname(ctx, "fn")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
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
                        "Policies": [
                            {
                                "PolicyName": "logs",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "logs:CreateLogGroup",
                                                "logs:CreateLogStream",
                                                "logs:PutLogEvents",
                                            ],
                                            "Resource": "*",
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "IdentityFunction": {
                    "Type": "AWS::Lambda::Function",
                    "DependsOn": "ExecRole",
                    "Properties": {
                        "FunctionName": function_name,
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Timeout": 15,
                        "MemorySize": 128,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {"ZipFile": _LAMBDA_CODE},
                    },
                },
            },
        }
    )

    _deploy_cfn(ctx, template, timeout_s=300.0)

    # Control-plane: the deployed role's trust document names lambda.amazonaws.com.
    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust = role["AssumeRolePolicyDocument"]
    trusted_services = {
        stmt["Principal"].get("Service")
        for stmt in trust["Statement"]
        if stmt.get("Effect") == "Allow"
    }
    assert "lambda.amazonaws.com" in trusted_services, (
        f"role {role_name} does not trust lambda.amazonaws.com: {trusted_services}"
    )

    # Data-plane: invoking the function proves Lambda actually ASSUMED the role (the
    # trust relationship works end to end), not just that the role document parses.
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"n": 21}).encode(),
    )
    assert not resp.get("FunctionError"), resp.get("FunctionError")
    payload = json.loads(resp["Payload"].read())
    assert payload["doubled"] == 42, f"expected doubled=42, got payload={payload}"
    assert f":assumed-role/{role_name}/" in payload["arn"], payload["arn"]


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
    template_body = template.read_text() if hasattr(template, "read_text") else template
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
