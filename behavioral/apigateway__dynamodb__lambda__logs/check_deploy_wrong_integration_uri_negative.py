"""deploy-wrong-integration-uri-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-wrong-integration-uri-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stack whose integration Uri names a nonexistent function reaches CREATE_COMPLETE but its method
    returns 5xx, while a sibling method wired to a real function succeeds and the intended function
    works when invoked directly."""
    function_name = _xname(ctx, "fn")
    ghost_name = function_name + "-ghost-target"
    good_function_name = _xname(ctx, "fn-good")
    api_name = _xname(ctx, "api")
    template = _build_template(
        function_name=function_name,
        ghost_name=ghost_name,
        good_function_name=good_function_name,
        api_name=api_name,
    )
    stack = _deploy_cfn(ctx, template)
    stage_url = ctx.api_url(stack["outputs"]["ApiId"], "test")
    api_url = f"{stage_url}/items"
    good_url = f"{stage_url}/good"

    status, body = _poll_until(
        lambda: _http_post(api_url, {"probe": "1"}),
        lambda r: r[0] != -1,
        timeout_s=60,
        interval_s=3.0,
        description="API returns a response once propagated",
    )
    assert status == 500, f"expected 500 (integration target does not exist), got {status}: {body}"

    # Twin control, same stack/stage/transport: a sibling method correctly wired to a real,
    # permitted Lambda must succeed. Without this, a target whose AWS_PROXY integration is
    # uniformly broken (always 500, regardless of target correctness) would pass the assertion
    # above for the wrong reason.
    good_status, good_body = _poll_until(
        lambda: _http_post(good_url, {"probe": "1"}),
        lambda r: r[0] != -1,
        timeout_s=60,
        interval_s=3.0,
        description="sibling (correctly-wired) API returns a response once propagated",
    )
    assert good_status == 200, f"expected 200 from the correctly-wired sibling method, got {good_status}: {good_body}"
    assert good_body.get("ok") is True, f"expected the good function's payload, got {good_body!r}"

    logs = ctx.client("logs")
    log_group_name = f"/aws/lambda/{function_name}"
    # The intended function must never have been reached through the API: its log group does not
    # exist yet (Lambda creates it lazily on first invocation).
    code, message = _client_error(lambda: logs.filter_log_events(logGroupName=log_group_name))
    assert code == "ResourceNotFoundException", (
        f"expected the intended function's log group to not exist (never invoked), got error code: {code!r}"
    )
    assert message == "The specified log group does not exist.", message

    # Second positive control: invoke the SAME intended function directly (bypassing API Gateway)
    # with an API-Gateway-proxy-shaped event, to prove it is fully functional and the failure
    # above is specifically the wiring, not a broken Lambda.
    lam = ctx.client("lambda")
    proxy_event = {
        "httpMethod": "POST",
        "path": "/items",
        "body": json.dumps({"probe": "direct"}),
        "headers": {},
        "requestContext": {},
    }
    invoke_resp = lam.invoke(
        FunctionName=function_name, Payload=json.dumps(proxy_event).encode("utf-8")
    )
    assert invoke_resp["StatusCode"] == 200, f"expected StatusCode 200, got {invoke_resp['StatusCode']}"
    assert "FunctionError" not in invoke_resp, f"unexpected FunctionError: {invoke_resp.get('FunctionError')}"
    payload = json.loads(invoke_resp["Payload"].read())
    assert payload.get("statusCode") == 200, f"expected statusCode 200 in payload, got {payload!r}"

    def _find_direct_log() -> list[dict[str, Any]]:
        try:
            return logs.filter_log_events(logGroupName=log_group_name).get("events", [])
        except ClientError:
            return []

    events = _poll_until(
        _find_direct_log,
        lambda evs: any("HANDLER_INVOKED" in e.get("message", "") for e in evs),
        timeout_s=60,
        interval_s=3.0,
        description="direct invoke produces a log line",
    )
    assert any("HANDLER_INVOKED" in e["message"] for e in events), (
        f"expected a HANDLER_INVOKED log line after the direct invoke, got events: {events!r}"
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

def handler(event, context):
    print("HANDLER_INVOKED")
    return {"statusCode": 200, "body": json.dumps({"ok": True})}
"""


def _build_template(*, function_name: str, ghost_name: str, good_function_name: str, api_name: str) -> str:
    role_name = function_name + "-role"
    good_role_name = good_function_name + "-role"
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
        "GoodExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": good_role_name,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                },
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
            },
        },
        "GoodFunction": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": "GoodExecRole",
            "Properties": {
                "FunctionName": good_function_name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["GoodExecRole", "Arn"]},
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
                    # Deliberately wrong: correct account/region shape, but points at a Lambda
                    # function name that was never deployed.
                    "Uri": {
                        "Fn::Sub": (
                            "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/"
                            "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:"
                            f"{ghost_name}/invocations"
                        )
                    },
                },
            },
        },
        "GoodResource": {
            "Type": "AWS::ApiGateway::Resource",
            "Properties": {
                "RestApiId": {"Ref": "RestApi"},
                "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                "PathPart": "good",
            },
        },
        "GoodMethod": {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "RestApi"},
                "ResourceId": {"Ref": "GoodResource"},
                "HttpMethod": "POST",
                "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "AWS_PROXY",
                    "IntegrationHttpMethod": "POST",
                    # Correctly wired: same transport/shape as Method above, but the target
                    # genuinely exists and is permitted — the twin control for the negative.
                    "Uri": {
                        "Fn::Sub": [
                            "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/${Arn}/invocations",
                            {"Region": {"Ref": "AWS::Region"}, "Arn": {"Fn::GetAtt": ["GoodFunction", "Arn"]}},
                        ]
                    },
                },
            },
        },
        "InvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": {"Ref": "Function"},
                "Principal": "apigateway.amazonaws.com",
                "SourceArn": {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/items"},
            },
        },
        "GoodInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": {"Ref": "GoodFunction"},
                "Principal": "apigateway.amazonaws.com",
                "SourceArn": {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/good"},
            },
        },
        "Deployment": {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": ["Method", "GoodMethod"],
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
