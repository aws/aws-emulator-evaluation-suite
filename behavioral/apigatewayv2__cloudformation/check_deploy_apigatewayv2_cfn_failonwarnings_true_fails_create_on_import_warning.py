"""deploy-apigatewayv2-cfn-failonwarnings-true-fails-create-on-import-warning."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-failonwarnings-true-fails-create-on-import-warning"

GROUP = "deploy"

SERVICES = ["apigatewayv2", "cloudformation"]

# API Gateway V2 import's own two warnings for an unsupported `http`-scheme security definition,
# forwarded verbatim through CloudFormation's resource handler. Only the two Request IDs and the
# RequestToken are per-call; the rest is a fixed string for this exact Body.
_WARNING_TEXT = (
    "Warnings found during import:\n"
    "\tUnsupported Security Scheme type 'http' for 'basicAuth'. Ignoring.\n"
    "\tMethod 'GET' on resource '/foo' specified security, but no custom authorizers were "
    "created and the extension x-amazon-apigateway-auth was not properly set. This method will "
    "be not be secured."
)
_REASON = re.compile(
    r'^Resource handler returned message: "' + re.escape(_WARNING_TEXT) + r" "
    r"\(Service: AmazonApiGatewayV2; Status Code: 400; Error Code: BadRequestException; "
    r"Request ID: [0-9a-f-]+; Proxy: null\) "
    r"\(Service: null; Status Code: 404; Error Code: BadRequestException; Request ID: null; "
    r'Proxy: null\)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: GeneralServiceException\)$"
)


def _body_with_warning(upstream_url: str) -> dict:
    return {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-failonwarnings", "version": "1.0"},
        "paths": {
            "/foo": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "security": [{"basicAuth": []}],
                    "x-amazon-apigateway-integration": {
                        "type": "HTTP_PROXY",
                        "httpMethod": "GET",
                        "uri": upstream_url,
                        "payloadFormatVersion": "1.0",
                    },
                }
            }
        },
        "components": {
            "securitySchemes": {"basicAuth": {"type": "http", "scheme": "basic"}}
        },
    }


def _template(fail_on_warnings: bool, upstream_url: str) -> str:
    props: dict[str, Any] = {"Body": _body_with_warning(upstream_url)}
    if fail_on_warnings:
        props["FailOnWarnings"] = True
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "WarnApi": {"Type": "AWS::ApiGatewayV2::Api", "Properties": props},
            "WarnApiStage": {
                "Type": "AWS::ApiGatewayV2::Stage",
                "Properties": {
                    "ApiId": {"Ref": "WarnApi"},
                    "StageName": "$default",
                    "AutoDeploy": True,
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Ref": "WarnApi"}}},
    })


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """``AWS::ApiGatewayV2::Api`` whose inline ``Body`` produces import warnings fails with API Gateway V2's
    ``Warnings found during import`` message when ``FailOnWarnings: true``, while the identical Body without
    it creates and serves the imported route, so ``FailOnWarnings`` alone decides the outcome."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    upstream, token = _mock_backend(ctx)

    # ---- the negative: FailOnWarnings true turns the warnings into a hard failure ----
    fail_stack = ctx.unique_name("sim2real-xsvc-failonwarn-bad-")
    cfn.create_stack(
        StackName=fail_stack,
        TemplateBody=_template(fail_on_warnings=True, upstream_url=upstream),
        OnFailure="DO_NOTHING",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, fail_stack))

    status = _poll_until(
        lambda: _stack_status(ctx, fail_stack),
        lambda s: s in {"CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_COMPLETE", "GONE"},
        timeout_s=300.0,
        description=f"stack {fail_stack} reaching a terminal create state",
    )
    assert status == "CREATE_FAILED", (
        f"FailOnWarnings=true against a Body that produces import warnings must fail the stack, "
        f"got {status!r}"
    )

    resources = cfn.describe_stack_resources(StackName=fail_stack)["StackResources"]
    failed = [r for r in resources if r["LogicalResourceId"] == "WarnApi"]
    assert len(failed) == 1 and failed[0]["ResourceStatus"] == "CREATE_FAILED", (
        f"the WarnApi resource must be the one that failed, stack resources report {resources!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    parsed = _REASON.match(reason)
    assert parsed is not None, (
        f"the WarnApi failure reason is not the expected forwarded import-warnings refusal: "
        f"{reason!r}"
    )

    # ---- the positive control: the SAME Body, FailOnWarnings simply omitted ----------
    ok_stack = ctx.unique_name("sim2real-xsvc-failonwarn-ok-")
    stack = _deploy_cfn(
        ctx, _template(fail_on_warnings=False, upstream_url=upstream), stack_name=ok_stack
    )
    api_id = stack["outputs"]["ApiId"]
    agw = ctx.client("apigatewayv2")
    routes = [r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items") or []]
    assert routes == ["GET /foo"], (
        f"the identical Body without FailOnWarnings must still import the declared route; "
        f"GetRoutes reports {routes!r}"
    )
    status, text = _poll_http(
        ctx.api_url(api_id, "$default") + "/foo",
        accept=lambda s: s == 200,
        verify=ctx.http_verify,
        description="GET /foo on the warning-tolerant API's $default stage",
    )
    assert text == token, (
        f"GET /foo on the API imported despite its warnings must proxy to this check's own "
        f"backend and return its token {token!r}; got {status}: {text[:300]!r}"
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
    try:
        return ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ]
    except ClientError as exc:
        if "does not exist" in exc.response.get("Error", {}).get("Message", ""):
            return "GONE"
        raise


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=300.0) -> None:
    ctx.client("cloudformation").delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template_body: str, *, stack_name: str, timeout_s: float = 300.0) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(method, url, *, verify=True, timeout_s=20):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(verify)) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _poll_http(url, *, accept, verify=True, timeout_s=180.0, interval_s=4.0, description="invoke URL"):
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while True:
        try:
            last = _http("GET", url, verify=verify)
        except OSError as exc:  # execute-api DNS/TLS still settling
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


def _mock_backend(ctx) -> tuple[str, str]:
    """A REST API MOCK stage the check owns, answering ANY / with 200 and a run-unique token --
    the upstream the imported HTTP_PROXY route proxies to, so a served response is attributable
    to this check's own backend rather than an external site."""
    ag = ctx.client("apigateway")
    token = ctx.unique_name("sim2real-xsvc-failonwarn-token-")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-failonwarn-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real:managed": "true"},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, rest_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=rest_id)["items"] if r["path"] == "/")
    ag.put_method(restApiId=rest_id, resourceId=root, httpMethod="ANY", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_id, resourceId=root, httpMethod="ANY", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_id, resourceId=root, httpMethod="ANY", statusCode="200")
    ag.put_integration_response(
        restApiId=rest_id, resourceId=root, httpMethod="ANY", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": token},
    )
    ag.create_deployment(restApiId=rest_id, stageName="backend")
    return ctx.rest_api_url(rest_id, "backend"), token


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
