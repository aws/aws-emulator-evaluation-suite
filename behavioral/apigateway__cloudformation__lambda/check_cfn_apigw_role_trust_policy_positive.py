"""cfn-apigw-role-trust-policy-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigw-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """API Gateway assumes a stack-created role that trusts apigateway.amazonaws.com as integration
    credentials: the call through the deployed stage succeeds and the function's log events land."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecRole": _lambda_exec_role(),
            "EchoFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Code": {"ZipFile": "def handler(event, context):\n    return {'ok': True}\n"},
                },
            },
            "ApiGwInvokeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                    "Policies": [
                        {
                            "PolicyName": "InvokeEcho",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": {"Fn::GetAtt": ["EchoFunction", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Ref": "AWS::StackName"}},
            },
            "EchoResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "echo",
                },
            },
            "EchoMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "EchoResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "AWS",
                        "IntegrationHttpMethod": "POST",
                        "Credentials": {"Fn::GetAtt": ["ApiGwInvokeRole", "Arn"]},
                        "PassthroughBehavior": "WHEN_NO_TEMPLATES",
                        "RequestTemplates": {"application/json": "{}"},
                        "Uri": {
                            "Fn::Sub": [
                                "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/${Arn}/invocations",
                                {
                                    "Region": {"Ref": "AWS::Region"},
                                    "Arn": {"Fn::GetAtt": ["EchoFunction", "Arn"]},
                                },
                            ]
                        },
                        "IntegrationResponses": [
                            {"StatusCode": "200", "ResponseTemplates": {"application/json": "$input.json('$')"}}
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "ApiDeployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": ["EchoMethod"],
                "Properties": {"RestApiId": {"Ref": "RestApi"}},
            },
            "ApiStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DeploymentId": {"Ref": "ApiDeployment"},
                    "StageName": "test",
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "RestApi"}},
            "FunctionName": {"Value": {"Ref": "EchoFunction"}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    api_id = result["outputs"]["RestApiId"]
    func_name = result["outputs"]["FunctionName"]

    url = _execute_api_url(ctx, api_id, "test", "/echo")
    status, body = _http_get(url)
    assert status == 200, f"expected 200, got {status}: {body!r}"
    payload = json.loads(body)
    assert payload["ok"] is True, f"expected {{'ok': True}} from the role-assumed Lambda invocation, got {payload!r}"

    # Deeper proof the assumed role really invoked the function (not a stub 200): the
    # function's own execution role produced real CloudWatch log events.
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{func_name}"

    def _has_log_events():
        try:
            streams = logs.describe_log_streams(
                logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1
            )["logStreams"]
        except ClientError:
            return False
        return bool(streams) and streams[0].get("lastEventTimestamp") is not None

    _poll_until(
        _has_log_events, lambda ok: ok, timeout_s=60.0, interval_s=3.0,
        description="lambda log stream with events",
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
