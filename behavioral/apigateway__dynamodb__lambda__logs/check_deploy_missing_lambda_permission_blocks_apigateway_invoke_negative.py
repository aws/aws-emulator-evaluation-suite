"""deploy-missing-lambda-permission-blocks-apigateway-invoke-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-missing-lambda-permission-blocks-apigateway-invoke-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AWS_PROXY integration without a Lambda permission fails its invocations and never reaches
    the function; adding the permission makes the identical request succeed."""
    function_name = _xname(ctx, "fn")
    api_name = _xname(ctx, "api")
    template = _build_template(function_name=function_name, api_name=api_name)
    stack = _deploy_cfn(ctx, template)
    api_id = stack["outputs"]["ApiId"]
    api_url = f"{ctx.api_url(api_id, 'test')}/items"

    status, body = _poll_until(
        lambda: _http_post(api_url, {"probe": "1"}),
        lambda r: r[0] != -1,
        timeout_s=60,
        interval_s=3.0,
        description="API returns a response (any status) once propagated",
    )
    assert status == 500, f"expected 500 (Lambda unreachable, no permission), got {status}: {body}"

    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    log_group_name = f"/aws/lambda/{function_name}"
    # The Lambda must never actually have been invoked: since Lambda creates its log group lazily
    # on first invocation, a function that was never reached has NO log group at all yet.
    code, message = _client_error(lambda: logs.filter_log_events(logGroupName=log_group_name))
    assert code == "ResourceNotFoundException", (
        f"expected the Lambda log group to not exist yet (never invoked), got code={code!r}"
    )
    assert message == "The specified log group does not exist.", message

    # Positive control: grant the missing permission on the SAME deployed API + function, and
    # confirm the identical request succeeds end-to-end.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*/items"
    lam.add_permission(
        FunctionName=function_name,
        StatementId="allow-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )

    status2, body2 = _poll_until(
        lambda: _http_post(api_url, {"probe": "2"}),
        lambda r: r[0] == 200,
        timeout_s=60,
        interval_s=3.0,
        description="API invoke succeeds after granting permission",
    )
    assert status2 == 200, f"expected 200 after fix, got {status2}: {body2}"
    assert body2.get("ok") is True, f"expected Lambda's real payload {{'ok': True}}, got {body2!r}"


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


def _client_error(fn) -> tuple[str, str | None]:
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


_HANDLER_CODE = """import json
import os

def handler(event, context):
    print("HANDLER_INVOKED")
    return {"statusCode": 200, "body": json.dumps({"ok": True})}
"""


def _build_template(*, function_name: str, api_name: str) -> str:
    role_name = function_name + "-role"
    resources: dict[str, Any] = {
        "ExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                },
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
            },
        },
        "Function": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": "ExecRole",
            "Properties": {
                "FunctionName": function_name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Timeout": 10,
                "Code": {"ZipFile": _HANDLER_CODE},
            },
        },
        "RestApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": api_name}},
        "ItemsResource": {
            "Type": "AWS::ApiGateway::Resource",
            "Properties": {
                "RestApiId": {"Ref": "RestApi"},
                "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                "PathPart": "items",
            },
        },
        "Method": {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "RestApi"},
                "ResourceId": {"Ref": "ItemsResource"},
                "HttpMethod": "POST",
                "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "AWS_PROXY",
                    "IntegrationHttpMethod": "POST",
                    "Uri": {
                        "Fn::Sub": (
                            "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/"
                            "${Function.Arn}/invocations"
                        )
                    },
                },
            },
        },
        # Deliberately NO AWS::Lambda::Permission resource here.
        "Deployment": {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": "Method",
            "Properties": {"RestApiId": {"Ref": "RestApi"}},
        },
        "Stage": {
            "Type": "AWS::ApiGateway::Stage",
            "Properties": {"RestApiId": {"Ref": "RestApi"}, "DeploymentId": {"Ref": "Deployment"}, "StageName": "test"},
        },
    }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "ApiId": {"Value": {"Ref": "RestApi"}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Function", "Arn"]}},
        },
    }
    return json.dumps(template)


def _http_post(url: str, payload: dict[str, Any], timeout: float = 10.0):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw
        return e.code, parsed
    except urllib.error.URLError as e:
        return -1, str(e)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
