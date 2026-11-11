"""cfn-apigw-lambda-proxy-integration-resource-binding-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigw-lambda-proxy-integration-resource-binding-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A proxy integration whose Uri uses one function's Fn::GetAtt ARN routes traffic to exactly that function,
    not to a second function the same stack creates."""
    marker = ctx.unique_name("sim2real-bind-")
    decoy_marker = ctx.unique_name("sim2real-decoy-")
    result = _deploy_cfn(ctx, _template(marker, decoy_marker))
    api_id = result["outputs"]["ApiId"]

    url = f"{ctx.rest_api_url(api_id, 'test')}/invoke"
    status, body = _poll_invoke_until(url, {200}, timeout_s=90, interval_s=3)
    assert status == 200, f"expected 200 from the bound Lambda, got {status}: {body}"
    payload = json.loads(body)
    assert payload == {"marker": marker}, (
        f"response did not come from the bound function: got {payload}, "
        f"expected the target's marker {marker!r} (never the decoy's {decoy_marker!r})"
    )


def _template(marker: str, decoy_marker: str) -> str:
    code = (
        "import json\n"
        "def handler(event, context):\n"
        f"    return {{'statusCode': 200, 'body': json.dumps({{'marker': {marker!r}}})}}\n"
    )
    decoy_code = (
        "import json\n"
        "def handler(event, context):\n"
        f"    return {{'statusCode': 200, 'body': json.dumps({{'marker': {decoy_marker!r}}})}}\n"
    )
    template = {
        "Resources": {
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": code},
                },
            },
            "DecoyFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": decoy_code},
                },
            },
            "Api": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": marker, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
            },
            "Res": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                    "PathPart": "invoke",
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ResourceId": {"Ref": "Res"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "AWS_PROXY",
                        "IntegrationHttpMethod": "POST",
                        "Uri": {
                            "Fn::Sub": "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${Fn.Arn}/invocations"
                        },
                    },
                },
            },
            "Permission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "Fn"},
                    "Principal": "apigateway.amazonaws.com",
                    "SourceArn": {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*/GET/invoke"},
                },
            },
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "Method",
                "Properties": {"RestApiId": {"Ref": "Api"}},
            },
            "Stage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {"RestApiId": {"Ref": "Api"}, "DeploymentId": {"Ref": "Deployment"}, "StageName": "test"},
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Ref": "Api"}},
            "FunctionName": {"Value": {"Ref": "Fn"}},
        },
    }
    return json.dumps(template)


def _invoke(url: str, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_invoke_until(url: str, target_statuses: set[int], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status, body = _invoke(url)
        last = (status, body)
        if status in target_statuses:
            return status, body
        time.sleep(interval_s)
    raise AssertionError(f"never observed status in {target_statuses}; last={last}")


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
    template_body = template
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
        lambda s: (s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}),
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
