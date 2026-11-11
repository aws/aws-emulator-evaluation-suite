"""cfn-apigw-role-missing-trust-principal-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-apigw-role-missing-trust-principal-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A non-proxy integration whose credentials role does not trust apigateway.amazonaws.com fails with a
    5xx and never invokes the function, while a sibling method whose role trusts it succeeds."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecRole": _lambda_exec_role(),
            "GoodFunction": _echo_function(),
            "BadFunction": _echo_function(),
            # Trust policy is WRONG: trusts ec2.amazonaws.com instead of apigateway.amazonaws.com.
            "BadInvokeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [_invoke_policy("BadFunction")],
                },
            },
            "GoodInvokeRole": {
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
                    "Policies": [_invoke_policy("GoodFunction")],
                },
            },
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Ref": "AWS::StackName"}},
            },
            "GoodResource": _resource("good"),
            "BadResource": _resource("bad"),
            "GoodMethod": _role_method("GoodResource", "GoodFunction", "GoodInvokeRole"),
            "BadMethod": _role_method("BadResource", "BadFunction", "BadInvokeRole"),
            "ApiDeployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": ["GoodMethod", "BadMethod"],
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
            "BadFunctionName": {"Value": {"Ref": "BadFunction"}},
            "GoodFunctionName": {"Value": {"Ref": "GoodFunction"}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    api_id = result["outputs"]["RestApiId"]
    bad_name = result["outputs"]["BadFunctionName"]
    good_name = result["outputs"]["GoodFunctionName"]
    logs = ctx.client("logs")

    # --- negative: BadInvokeRole's trust policy omits apigateway.amazonaws.com ---
    bad_url = _execute_api_url(ctx, api_id, "test", "/bad")
    bad_status, bad_body = _http_get(bad_url)
    assert bad_status == 500, f"expected 500 for an unassumable role, got {bad_status}: {bad_body!r}"

    def _bad_has_logs():
        try:
            streams = logs.describe_log_streams(logGroupName=f"/aws/lambda/{bad_name}")["logStreams"]
        except ClientError:
            return False
        return any(s.get("lastEventTimestamp") is not None for s in streams)

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        assert not _bad_has_logs(), "BadFunction was invoked despite an unassumable role"
        time.sleep(2.0)

    # --- positive control: GoodInvokeRole trusts apigateway.amazonaws.com and IS assumed ---
    good_url = _execute_api_url(ctx, api_id, "test", "/good")
    good_status, good_body = _http_get(good_url)
    assert good_status == 200, f"expected 200, got {good_status}: {good_body!r}"
    good_payload = json.loads(good_body)
    assert good_payload["ok"] is True, f"expected ok=True from GoodFunction, got {good_payload!r}"

    def _good_has_logs():
        try:
            streams = logs.describe_log_streams(
                logGroupName=f"/aws/lambda/{good_name}", orderBy="LastEventTime", descending=True, limit=1
            )["logStreams"]
        except ClientError:
            return False
        return bool(streams) and streams[0].get("lastEventTimestamp") is not None

    _poll_until(
        _good_has_logs, lambda ok: ok, timeout_s=60.0, interval_s=3.0,
        description="GoodFunction log stream with events",
    )


def _echo_function() -> dict[str, Any]:
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "Handler": "index.handler",
            "Runtime": "python3.12",
            "Timeout": 30,
            "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
            "Code": {"ZipFile": "def handler(event, context):\n    return {'ok': True}\n"},
        },
    }


def _invoke_policy(function_logical_id: str) -> dict[str, Any]:
    return {
        "PolicyName": f"Invoke{function_logical_id}",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": {"Fn::GetAtt": [function_logical_id, "Arn"]},
                }
            ],
        },
    }


def _resource(path_part: str) -> dict[str, Any]:
    return {
        "Type": "AWS::ApiGateway::Resource",
        "Properties": {
            "RestApiId": {"Ref": "RestApi"},
            "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
            "PathPart": path_part,
        },
    }


def _role_method(resource_logical_id: str, function_logical_id: str, role_logical_id: str) -> dict[str, Any]:
    return {
        "Type": "AWS::ApiGateway::Method",
        "Properties": {
            "RestApiId": {"Ref": "RestApi"},
            "ResourceId": {"Ref": resource_logical_id},
            "HttpMethod": "GET",
            "AuthorizationType": "NONE",
            "Integration": {
                "Type": "AWS",
                "IntegrationHttpMethod": "POST",
                "Credentials": {"Fn::GetAtt": [role_logical_id, "Arn"]},
                "PassthroughBehavior": "WHEN_NO_TEMPLATES",
                "RequestTemplates": {"application/json": "{}"},
                "Uri": {
                    "Fn::Sub": [
                        "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/${Arn}/invocations",
                        {"Region": {"Ref": "AWS::Region"}, "Arn": {"Fn::GetAtt": [function_logical_id, "Arn"]}},
                    ]
                },
                "IntegrationResponses": [
                    {"StatusCode": "200", "ResponseTemplates": {"application/json": "$input.json('$')"}}
                ],
            },
            "MethodResponses": [{"StatusCode": "200"}],
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
