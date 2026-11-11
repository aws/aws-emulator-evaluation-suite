"""cfn-apigw-stack-update-swap-lambda-target-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigw-stack-update-swap-lambda-target-positive"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudformation", "lambda"]


def _template(active_target: str, deployment_logical_id: str) -> dict[str, Any]:
    """Build the stack template for a given active Lambda target ('A' or 'B') and Deployment
    LOGICAL ID. AWS::ApiGateway::Deployment has NO property that forces Replacement on a
    config-only change (Description/StageName are both "No interruption" per the CFN resource
    reference), so the only template-level way to force a genuinely NEW deployment snapshot is
    to change the Deployment resource's LOGICAL ID between updates — CloudFormation then
    deletes the old deployment and creates a new one capturing the current (updated)
    integration, exactly like the well-known "versioned logical id" pattern teams use for raw
    CFN API Gateway deployments."""
    is_b = active_target == "B"
    target_ref = "FuncB" if is_b else "FuncA"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecRole": _lambda_exec_role(),
            "FuncA": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Code": {
                        "ZipFile": (
                            "import json\n"
                            "def handler(event, context):\n"
                            "    return {'statusCode': 200, 'body': json.dumps({'source': 'A'})}\n"
                        )
                    },
                },
            },
            "FuncB": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Code": {
                        "ZipFile": (
                            "import json\n"
                            "def handler(event, context):\n"
                            "    return {'statusCode': 200, 'body': json.dumps({'source': 'B'})}\n"
                        )
                    },
                },
            },
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Ref": "AWS::StackName"}},
            },
            "SwapResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "swap",
                },
            },
            "SwapMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "SwapResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "AWS_PROXY",
                        "IntegrationHttpMethod": "POST",
                        "Uri": {
                            "Fn::Sub": [
                                "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/${Arn}/invocations",
                                {
                                    "Region": {"Ref": "AWS::Region"},
                                    "Arn": {"Fn::GetAtt": [target_ref, "Arn"]},
                                },
                            ]
                        },
                    },
                },
            },
            "InvokePermissionA": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "FuncA"},
                    "Principal": "apigateway.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/*"
                    },
                },
            },
            "InvokePermissionB": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "FuncB"},
                    "Principal": "apigateway.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/*"
                    },
                },
            },
            deployment_logical_id: {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": ["SwapMethod"],
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "Description": f"revision targeting {active_target}",
                },
            },
            "ApiStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DeploymentId": {"Ref": deployment_logical_id},
                    "StageName": "test",
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "RestApi"}},
            "DeploymentId": {"Value": {"Ref": deployment_logical_id}},
        },
    }


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stack update that points the integration at a new function and uses a new Deployment logical ID
    makes the same stage route calls to the new function, not the old one."""
    initial_template = json.dumps(_template("A", "ApiDeploymentA"))
    result = _deploy_cfn(ctx, initial_template)
    api_id = result["outputs"]["RestApiId"]
    stack_name = result["stack_name"]
    initial_deployment_id = result["outputs"]["DeploymentId"]

    url = _execute_api_url(ctx, api_id, "test", "/swap")
    status, body = _http_get(url)
    assert status == 200, f"expected 200 from initial deployment, got {status}: {body!r}"
    initial_source = json.loads(body)["source"]
    assert initial_source == "A", f"expected initial target 'A', got {initial_source!r}"

    updated_template = json.dumps(_template("B", "ApiDeploymentB"))
    updated = _update_stack_and_wait(ctx, stack_name, updated_template)
    new_deployment_id = updated["outputs"]["DeploymentId"]
    assert new_deployment_id != initial_deployment_id, "expected a NEW deployment after swap"

    def _probe():
        s, b = _http_get(url)
        return s, b

    def _routed_to_b(result_tuple):
        s, b = result_tuple
        return s == 200 and json.loads(b)["source"] == "B"

    final_status, final_body = _poll_until(
        _probe, _routed_to_b, timeout_s=60.0, interval_s=3.0,
        description="stage routed to swapped-in FuncB",
    )
    final_source = json.loads(final_body)["source"]
    assert final_source == "B", f"expected swapped target 'B', got {final_source!r}"


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
        _status, lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120, interval_s=5.0, description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
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
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s, interval_s=5.0, description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _update_stack_and_wait(
    ctx, stack_name: str, template: str, *, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    """Update an existing stack (created via ``_deploy_cfn``) and wait for it to settle into a
    terminal UPDATE state. Reuses ``_deploy_cfn``'s teardown (already registered)."""
    cfn = ctx.client("cloudformation")
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template,
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    cfn.update_stack(**kwargs)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=timeout_s, interval_s=5.0, description=f"CFN stack update {stack_name}",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update {stack_name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


def _lambda_exec_role() -> dict[str, Any]:
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
        },
    }


def _http_get(url: str, timeout: float = 20.0) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _execute_api_url(ctx, api_id: str, stage: str, path: str) -> str:
    return f"{ctx.rest_api_url(api_id, stage)}{path}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
