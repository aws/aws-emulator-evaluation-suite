"""deploy-apigateway-account-cloudwatch-role-configured."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-account-cloudwatch-role-configured"
GROUP = "deployment-wiring"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A CFN-deployed AWS::ApiGateway::Account resource must actually set the account-level
    CloudWatch role used for API Gateway execution/access logging — verified via
    apigateway.get_account(), not just that the stack reached CREATE_COMPLETE."""
    apigw = ctx.client("apigateway")

    # AWS::ApiGateway::Account is an account-global singleton (one cloudwatchRoleArn per
    # account per region) — capture and restore it so this check does not leave the account
    # pointed at a role that the stack deletion below is about to remove.
    original_role_arn = apigw.get_account().get("cloudwatchRoleArn") or ""
    ctx.on_cleanup(
        lambda: apigw.update_account(
            patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original_role_arn}]
        )
    )

    role_name = _xname(ctx, "apigw-cw-role")
    template = _build_template(role_name=role_name)
    stack = _deploy_cfn(ctx, template)
    role_arn = stack["outputs"]["RoleArn"]
    assert role_arn.split("/")[-1] == role_name, f"CFN output RoleArn {role_arn!r} does not name {role_name!r}"

    def _account_role() -> str | None:
        return apigw.get_account().get("cloudwatchRoleArn")

    observed = _poll_until(
        _account_role,
        lambda arn: arn == role_arn,
        timeout_s=60,
        interval_s=3.0,
        description="apigateway account cloudwatchRoleArn matches deployed role",
    )
    assert observed == role_arn, f"apigateway account cloudwatchRoleArn={observed!r}, expected {role_arn!r}"

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    principal = role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"]
    if isinstance(principal, list):
        assert "apigateway.amazonaws.com" in principal, f"trust policy principals {principal!r} missing apigateway.amazonaws.com"
    else:
        assert principal == "apigateway.amazonaws.com", f"trust policy principal is {principal!r}, expected apigateway.amazonaws.com"

    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert any(p["PolicyName"] == "AmazonAPIGatewayPushToCloudWatchLogs" for p in attached), (
        f"CwRole has no AmazonAPIGatewayPushToCloudWatchLogs attachment; attached={[p['PolicyName'] for p in attached]!r}"
    )


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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


def _build_template(*, role_name: str) -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "CwRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "apigateway.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
                    ],
                    "Tags": [
                        {"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()
                    ],
                },
            },
            "ApiGwAccount": {
                "Type": "AWS::ApiGateway::Account",
                "Properties": {"CloudWatchRoleArn": {"Fn::GetAtt": ["CwRole", "Arn"]}},
            },
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["CwRole", "Arn"]}}},
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
