"""deploy-cfn-lambda-execution-role-trusts-lambda-service-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-execution-role-trusts-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Lambda execution role's AssumeRolePolicyDocument trusts
    lambda.amazonaws.com; the deployed function reaches Active state and a real invoke
    succeeds (proving Lambda actually assumed the role, not just that CFN accepted it)."""
    stack = _deploy_cfn(ctx, json.dumps(_template()), timeout_s=180)
    outputs = stack["outputs"]

    iam = ctx.client("iam")
    role_name = outputs["RoleName"]
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    statement = trust_doc["Statement"][0]
    assert statement["Effect"] == "Allow", f"expected trust statement to Allow, got {statement}"
    principal_service = statement["Principal"]["Service"]
    if isinstance(principal_service, str):
        assert principal_service == "lambda.amazonaws.com", (
            f"expected sole trusted principal lambda.amazonaws.com, got {principal_service!r}"
        )
    else:
        assert "lambda.amazonaws.com" in principal_service, (
            f"expected lambda.amazonaws.com among trusted principals, got {principal_service!r}"
        )

    lam = ctx.client("lambda")
    cfg = _poll_until(
        lambda: lam.get_function(FunctionName=outputs["FunctionName"])["Configuration"],
        lambda c: c["State"] == "Active" and c["LastUpdateStatus"] == "Successful",
        timeout_s=90,
        interval_s=3.0,
        description="Lambda function reaching Active state",
    )
    assert cfg["Role"] == role["Arn"], (
        f"expected function role {role['Arn']!r} (from CFN Fn::GetAtt), got {cfg['Role']!r}"
    )

    resp = lam.invoke(
        FunctionName=outputs["FunctionName"],
        Payload=json.dumps({"greeting": "hello-sim2real"}).encode(),
    )
    assert "FunctionError" not in resp, f"expected invoke to succeed, got FunctionError: {resp}"
    body = json.loads(resp["Payload"].read())
    assert body["received"] == {"greeting": "hello-sim2real"}, (
        f"expected handler to echo the invoke payload, got {body!r}"
    )


def _template() -> dict[str, Any]:
    lambda_code = (
        "def handler(event, context):\n"
        "    return {'received': event}\n"
    )
    return {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "TrustFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Fn::Sub": "${AWS::StackName}-fn"},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 15,
                    "Code": {"ZipFile": lambda_code},
                },
            },
        },
        "Outputs": {
            "RoleName": {"Value": {"Ref": "ExecRole"}},
            "FunctionName": {"Value": {"Ref": "TrustFn"}},
        },
    }


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
