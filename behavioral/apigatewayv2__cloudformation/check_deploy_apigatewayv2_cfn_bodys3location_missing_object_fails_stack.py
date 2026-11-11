"""deploy-apigatewayv2-cfn-bodys3location-missing-object-fails-stack."""
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

CHECK = "deploy-apigatewayv2-cfn-bodys3location-missing-object-fails-stack"

GROUP = "deploy"

SERVICES = ["apigatewayv2", "cloudformation"]

# CloudFormation's wrapping of API Gateway V2's own ImportApi refusal. The only run-specific
# value is the RequestToken; every other field is a fixed string API Gateway V2 always returns
# for an S3 location it cannot read.
_REASON = re.compile(
    r'^Resource handler returned message: "Unable to parse BodyS3Location '
    r"\(Service: null; Status Code: 0; Error Code: null; Request ID: null; Proxy: null\) "
    r'\(Service: null; Status Code: 404; Error Code: BadRequestException; Request ID: null; '
    r'Proxy: null\)" \(RequestToken: (?P<token>[0-9a-f-]+), '
    r"HandlerErrorCode: GeneralServiceException\)$"
)


def _good_body(upstream_url: str) -> dict:
    return {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-bodys3-good", "version": "1.0"},
        "paths": {
            "/ok": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "HTTP_PROXY",
                        "httpMethod": "GET",
                        "uri": upstream_url,
                        "payloadFormatVersion": "1.0",
                    },
                }
            }
        },
    }


def _template(bucket: str, key: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "S3Api": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"BodyS3Location": {"Bucket": bucket, "Key": key}},
            },
            "S3ApiStage": {
                "Type": "AWS::ApiGatewayV2::Stage",
                "Properties": {
                    "ApiId": {"Ref": "S3Api"},
                    "StageName": "$default",
                    "AutoDeploy": True,
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Ref": "S3Api"}}},
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
    """``AWS::ApiGatewayV2::Api`` with a ``BodyS3Location`` naming a missing S3 object fails the stack at that
    resource with API Gateway V2's ``Unable to parse BodyS3Location`` refusal, while a second stack naming
    an existing key in the same bucket succeeds and serves the imported route."""
    ctx.verify_account_safety()
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-xsvc-bodys3loc-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region that refuses an explicit LocationConstraint of itself.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    upstream, token = _mock_backend(ctx)

    # ---- the negative: BodyS3Location names a key that was never put -----------------
    bad_stack = ctx.unique_name("sim2real-xsvc-bodys3loc-bad-")
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bucket, "never-uploaded.json"),
        OnFailure="DO_NOTHING",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, bad_stack))

    status = _poll_until(
        lambda: _stack_status(ctx, bad_stack),
        lambda s: s in {"CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_COMPLETE", "GONE"},
        timeout_s=300.0,
        description=f"stack {bad_stack} reaching a terminal create state",
    )
    assert status == "CREATE_FAILED", (
        f"a BodyS3Location naming a never-uploaded key must fail the stack, got {status!r}"
    )

    resources = cfn.describe_stack_resources(StackName=bad_stack)["StackResources"]
    failed = [r for r in resources if r["LogicalResourceId"] == "S3Api"]
    assert len(failed) == 1 and failed[0]["ResourceStatus"] == "CREATE_FAILED", (
        f"the S3Api resource must be the one that failed, stack resources report {resources!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    parsed = _REASON.match(reason)
    assert parsed is not None, (
        f"the S3Api failure reason is not the expected forwarded BodyS3Location refusal: "
        f"{reason!r}"
    )

    # ---- the positive control: same bucket, a key that DOES exist, a SEPARATE stack ---
    s3.put_object(
        Bucket=bucket, Key="good.json", Body=json.dumps(_good_body(upstream)).encode()
    )
    good_stack = ctx.unique_name("sim2real-xsvc-bodys3loc-good-")
    stack = _deploy_cfn(ctx, _template(bucket, "good.json"), stack_name=good_stack)
    api_id = stack["outputs"]["ApiId"]
    agw = ctx.client("apigatewayv2")
    routes = [r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items") or []]
    assert routes == ["GET /ok"], (
        f"the same BodyS3Location mechanism against an object that exists must import the "
        f"declared route; GetRoutes reports {routes!r}"
    )
    status, text = _poll_http(
        ctx.api_url(api_id, "$default") + "/ok",
        accept=lambda s: s == 200,
        verify=ctx.http_verify,
        description="GET /ok on the imported API's $default stage",
    )
    assert text == token, (
        f"GET /ok on the imported API must proxy to this check's own backend and return its "
        f"token {token!r}; got {status}: {text[:300]!r}"
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
    token = ctx.unique_name("sim2real-xsvc-bodys3loc-token-")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-bodys3loc-backend-"),
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


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
