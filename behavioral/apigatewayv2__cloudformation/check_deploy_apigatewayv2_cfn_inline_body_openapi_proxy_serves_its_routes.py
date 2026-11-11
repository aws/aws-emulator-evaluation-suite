"""deploy-apigatewayv2-cfn-inline-body-openapi-proxy-serves-its-routes."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-inline-body-openapi-proxy-serves-its-routes"

GROUP = "deploy"

SERVICES = ["apigatewayv2", "cloudformation"]


def _handler_code() -> str:
    return (
        "import json\n\n\n"
        "def lambda_handler(event, context):\n"
        "    rc = event.get('requestContext') or {}\n"
        "    return {\n"
        "        'statusCode': 200,\n"
        "        'headers': {'Content-Type': 'application/json'},\n"
        "        'body': json.dumps(\n"
        "            {'routeKey': rc.get('routeKey'), 'rawPath': event.get('rawPath')}\n"
        "        ),\n"
        "    }\n"
    )


def _body() -> dict:
    integration = {
        "type": "AWS_PROXY",
        "httpMethod": "POST",
        "payloadFormatVersion": "2.0",
        "uri": {
            "Fn::Sub": (
                "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/"
                "${EchoFunction.Arn}/invocations"
            )
        },
    }
    return {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-body-import", "version": "1.0"},
        "paths": {
            "/alpha": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": integration,
                }
            },
            "/beta": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": integration,
                }
            },
        },
    }


def _template(role_name: str, fn_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "Path": "/sim2real/",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "inline",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "arn:aws:logs:*:*:*",
                            }],
                        },
                    }],
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                },
            },
            "EchoFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.lambda_handler",
                    "Role": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "Timeout": 20,
                    "MemorySize": 128,
                    "Code": {"ZipFile": _handler_code()},
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                },
            },
            "Api": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"Body": _body()},
            },
            "InvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Fn::GetAtt": ["EchoFunction", "Arn"]},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "apigateway.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": (
                            "arn:${AWS::Partition}:execute-api:${AWS::Region}:"
                            "${AWS::AccountId}:${Api}/*/*"
                        )
                    },
                },
            },
            "Stage": {
                "Type": "AWS::ApiGatewayV2::Stage",
                "Properties": {
                    "ApiId": {"Ref": "Api"},
                    "StageName": "$default",
                    "AutoDeploy": True,
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Ref": "Api"}}},
    })


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An ``AWS::ApiGatewayV2::Api`` with an inline OpenAPI ``Body`` (two AWS_PROXY paths) yields
    exactly those routes and integrations, each HTTPS request reaches the right Lambda, and an
    undeclared path answers 404."""
    ctx.verify_account_safety()
    role_name = ctx.unique_name("sim2real-xsvc-bodyimport-role-")
    fn_name = ctx.unique_name("sim2real-xsvc-bodyimport-fn-")
    template = _template(role_name, fn_name)

    # Registered BEFORE the stack create, so LIFO reaps the function's log group AFTER the stack
    # delete removes the function itself -- DeleteFunction never removes /aws/lambda/<fn>.
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, [fn_name]))
    stack = _deploy_cfn(ctx, template, stack_name=ctx.unique_name("sim2real-xsvc-bodyimport-stk-"))
    api_id = stack["outputs"]["ApiId"]

    agw = ctx.client("apigatewayv2")
    got_api = agw.get_api(ApiId=api_id)
    assert got_api.get("ProtocolType") == "HTTP", (
        f"an Api created from an OpenAPI Body with no explicit ProtocolType must infer HTTP, "
        f"GetApi reports {got_api.get('ProtocolType')!r}"
    )
    api_endpoint = ctx.stage_url(got_api["ApiEndpoint"], "$default")

    route_keys = sorted(r["RouteKey"] for r in _paginate(agw, "get_routes", "Items", ApiId=api_id))
    assert route_keys == ["GET /alpha", "GET /beta"], (
        f"the imported Body declares exactly /alpha and /beta under GET; GetRoutes reports "
        f"{route_keys!r}"
    )

    integrations = _paginate(agw, "get_integrations", "Items", ApiId=api_id)
    assert len(integrations) == 2, (
        f"import creates one Integration PER path even though both carry an identical "
        f"x-amazon-apigateway-integration block; GetIntegrations reports "
        f"{len(integrations)} item(s)"
    )
    for integ in integrations:
        assert integ.get("IntegrationType") == "AWS_PROXY", (
            f"every integration's type is the Body's AWS_PROXY, GetIntegration reports "
            f"{integ.get('IntegrationType')!r}"
        )
        assert fn_name in (integ.get("IntegrationUri") or ""), (
            f"every integration must target the stack's own Lambda {fn_name!r}, GetIntegration "
            f"reports IntegrationUri={integ.get('IntegrationUri')!r}"
        )

    status, text = _poll_http(
        f"{api_endpoint}/alpha",
        accept=lambda s: s == 200,
        description="GET /alpha on the Body-imported API",
    )
    assert status == 200, f"GET /alpha must be served, got {status}: {text[:300]!r}"
    assert json.loads(text) == {"routeKey": "GET /alpha", "rawPath": "/alpha"}, (
        f"GET /alpha must be proxied to the echo Lambda with its own route key, got {text[:300]!r}"
    )

    status, text = _http("GET", f"{api_endpoint}/beta")
    assert status == 200, f"GET /beta must be served, got {status}: {text[:300]!r}"
    assert json.loads(text) == {"routeKey": "GET /beta", "rawPath": "/beta"}, (
        f"GET /beta must be proxied to the echo Lambda with its own route key, got {text[:300]!r}"
    )

    status, text = _http("GET", f"{api_endpoint}/gamma")
    assert status == 404, (
        f"a path the Body never declared must not be served; GET /gamma got {status}: "
        f"{text[:300]!r}"
    )


def _http(method, url, body=None, headers=None, timeout_s=20):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _poll_http(url, *, accept, timeout_s=180.0, interval_s=4.0, description="invoke URL"):
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while True:
        try:
            last = _http("GET", url)
        except OSError as exc:
            last = (None, f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[1][:300]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack_status(ctx, stack_name):
    from botocore.exceptions import ClientError

    try:
        return ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ]
    except ClientError:
        return "GONE"


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=600.0) -> None:
    ctx.client("cloudformation").delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template_body: str, *, stack_name: str, timeout_s: float = 600.0) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, timeout_s=timeout_s))
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name} reaching a terminal create state",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"stack {stack_name} ended in {stack['StackStatus']}: "
            f"{stack.get('StackStatusReason', '(no reason given)')}"
        )
    return {
        "stack_name": stack_name,
        "outputs": {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])},
    }


def _paginate(client, op, key, **kwargs):
    items, token = [], None
    while True:
        resp = getattr(client, op)(**kwargs, **({"NextToken": token} if token else {}))
        items += resp.get(key, [])
        token = resp.get("NextToken")
        if not token:
            return items


def _reap_log_groups(ctx, names):
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can RECREATE it
    after a delete. One net per check deletes every group, then watches all of them together
    until each has stayed absent for 20s (bounded at 60s), and raises if one never does."""
    _leaks: list = []
    import sys

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    groups = [f"/aws/lambda/{n}" for n in names]
    absent_since = {g: None for g in groups}
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        for g in groups:
            try:
                logs.delete_log_group(logGroupName=g)
                absent_since[g] = None
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
                if absent_since[g] is None:
                    absent_since[g] = now
        if all(t is not None and now - t >= 20.0 for t in absent_since.values()):
            if _leaks:
                raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                    (e for _, e in _leaks if e is not None), None
                )
            return
        time.sleep(2.0)
    for g, t in absent_since.items():
        if t is None or time.monotonic() - t < 20.0:
            _leaks.append((f"log group {g} kept reappearing after delete", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
