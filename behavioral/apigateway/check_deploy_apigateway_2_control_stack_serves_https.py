"""deploy-apigateway-2-control-stack-serves-https."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-apigateway-2-control-stack-serves-https"
GROUP = "deploy-apigw-rollback"
SERVICES = ["apigateway"]

_STAGE = "sim2real"


def _template(marker: str) -> str:
    """The rollback checks' base template WITHOUT the bad resource:
    RestApi -> /echo Resource -> GET MOCK Method -> Deployment -> Stage."""
    resources = {
        "Api": {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}},
        },
        "EchoResource": {
            "Type": "AWS::ApiGateway::Resource",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                "PathPart": "echo",
            },
        },
        "EchoMethod": {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ResourceId": {"Ref": "EchoResource"},
                "HttpMethod": "GET",
                "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "MOCK",
                    "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                    "IntegrationResponses": [{
                        "StatusCode": "200",
                        "ResponseTemplates": {"application/json": json.dumps({"marker": marker})},
                    }],
                },
                "MethodResponses": [{"StatusCode": "200"}],
            },
        },
        "ApiDeployment": {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": ["EchoMethod"],
            "Properties": {"RestApiId": {"Ref": "Api"}},
        },
        "ApiStage": {
            "Type": "AWS::ApiGateway::Stage",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "DeploymentId": {"Ref": "ApiDeployment"},
                "StageName": _STAGE,
            },
        },
    }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A RestApi/Method/Deployment/Stage stack reaches CREATE_COMPLETE and an HTTPS GET to the stage's
    invoke URL returns 200 with the MOCK integration's mapped marker body."""
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    marker = ctx.unique_name("marker-1-")
    stack_name = ctx.unique_name("sim2real-behav-agw-ctl-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(marker),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_settled(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"control stack settled at {status!r}, expected CREATE_COMPLETE"

    api_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]
    named = sorted(
        item["id"]
        for page in ag.get_paginator("get_rest_apis").paginate()
        for item in page.get("items", [])
        if item.get("name") == f"{stack_name}-api"
    )
    assert named == [api_id], (
        f"GetRestApis name search for {stack_name + '-api'!r} returned {named!r}, "
        f"expected exactly the stack's RestApi [{api_id!r}]"
    )
    stage = ag.get_stage(restApiId=api_id, stageName=_STAGE)
    deployment_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="ApiDeployment"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert stage["deploymentId"] == deployment_id, (
        f"stage points at {stage['deploymentId']!r}, expected the stack's deployment "
        f"{deployment_id!r}"
    )

    url = _apigw_url(ctx, api_id, _STAGE, "echo")
    status_code, headers, text = _poll_http(
        url, lambda s, h, t: s == 200,
        description=f"GET {url} to serve the CloudFormation-deployed MOCK integration",
    )
    assert status_code == 200, f"expected 200 from the deployed stage, got {status_code}: {text!r}"
    assert headers.get("content-type", "").startswith("application/json"), (
        f"expected an application/json content-type, got {headers.get('content-type')!r}"
    )
    body = json.loads(text)
    assert body == {"marker": marker}, f"stage served {body!r}, expected {{'marker': {marker!r}}}"


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text).

    A connection-level failure (a brand-new execute-api hostname not yet resolvable) is
    status None so a poll keeps going; it is never mistaken for an HTTP status."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        return (None, {}, repr(exc))


def _poll_http(url, predicate, *, method="GET", timeout_s=180.0, interval_s=3.0,
               description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _wait_settled(cfn, stack_id: str, timeout_s: float = 600.0, interval_s: float = 5.0) -> str:
    """Poll until the stack leaves every *_IN_PROGRESS state; return the settled status."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} did not settle within {timeout_s}s (last={status!r})")


def _delete_stack(cfn, stack_id: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_id)
        status = _wait_settled(cfn, stack_id)
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(
            f"cloudformation stack {stack_id}: delete failed: {exc!r}"
        ) from exc
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"cloudformation stack {stack_id}: delete settled at {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
