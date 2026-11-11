"""cfn-apigw-wrong-integration-uri-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-apigw-wrong-integration-uri-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An integration URI naming a nonexistent function deploys through CloudFormation but every call
    fails with a 5xx, while a sibling method targeting a real, permitted function succeeds."""
    bogus_function_name = ctx.unique_name("sim2real-xsvc-nonexistent-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecRole": _lambda_exec_role(),
            "GoodFunction": {
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
                            "    return {'statusCode': 200, 'body': json.dumps({'ok': True})}\n"
                        )
                    },
                },
            },
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Ref": "AWS::StackName"}},
            },
            "GoodResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "good",
                },
            },
            "BadResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "bad",
                },
            },
            "GoodMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "GoodResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "AWS_PROXY",
                        "IntegrationHttpMethod": "POST",
                        "Uri": {
                            "Fn::Sub": [
                                "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/${Arn}/invocations",
                                {"Region": {"Ref": "AWS::Region"}, "Arn": {"Fn::GetAtt": ["GoodFunction", "Arn"]}},
                            ]
                        },
                    },
                },
            },
            "BadMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "BadResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "AWS_PROXY",
                        "IntegrationHttpMethod": "POST",
                        # References a Lambda ARN that does not exist in this account/region.
                        "Uri": {
                            "Fn::Sub": (
                                "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/"
                                "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:"
                                + bogus_function_name
                                + "/invocations"
                            )
                        },
                    },
                },
            },
            "GoodPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "GoodFunction"},
                    "Principal": "apigateway.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/*"
                    },
                },
            },
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
        "Outputs": {"RestApiId": {"Value": {"Ref": "RestApi"}}},
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    api_id = result["outputs"]["RestApiId"]

    # --- negative: the target Lambda ARN in the Integration Uri does not exist ---
    lam = ctx.client("lambda")

    code, message = _error(lambda: lam.get_function(FunctionName=bogus_function_name))
    assert code == "ResourceNotFoundException", (
        f"the wrong-URI target must genuinely not exist — no delivery is possible, got {code!r}"
    )
    expected_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bogus_function_name}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    bad_url = _execute_api_url(ctx, api_id, "test", "/bad")
    bad_status, bad_body = _http_get(bad_url)
    assert bad_status == 500, f"expected 500 for a nonexistent target, got {bad_status}: {bad_body!r}"

    # --- positive control: same stack/stage, Uri targets a real permitted function ---
    good_url = _execute_api_url(ctx, api_id, "test", "/good")
    good_status, good_body = _http_get(good_url)
    assert good_status == 200, f"expected 200, got {good_status}: {good_body!r}"
    good_json = json.loads(good_body)
    assert good_json["ok"] is True, f"expected {{'ok': True}} from the good integration, got {good_json!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error(fn) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a call that
    succeeds fails the check."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


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
