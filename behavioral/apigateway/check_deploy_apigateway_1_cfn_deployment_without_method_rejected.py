"""deploy-apigateway-1-cfn-deployment-without-method-rejected."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-1-cfn-deployment-without-method-rejected"
GROUP = "deploy-apigw-snapshot-ordering"
SERVICES = ["apigateway"]

_STAGE = "prod"
_HANDLER_CODE = re.compile(r"HandlerErrorCode: (\w+)")
_STATUS_CODE = re.compile(r"Status Code: (\d+)")


def _template(*, with_method: bool) -> str:
    """RestApi + /old Resource + Deployment (+ the GET Method and a Stage in the control).

    The broken variant differs by exactly one thing: no Method exists when the Deployment
    is created, which is the state ``DependsOn: <Method>`` exists to prevent.
    """
    resources = {
        "Api": {"Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}}},
        "OldResource": {"Type": "AWS::ApiGateway::Resource",
                        "Properties": {"RestApiId": {"Ref": "Api"},
                                       "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                                       "PathPart": "old"}},
        "Deployment": {"Type": "AWS::ApiGateway::Deployment",
                       "DependsOn": ["OldResource"] + (["OldMethod"] if with_method else []),
                       "Properties": {"RestApiId": {"Ref": "Api"}}},
    }
    if with_method:
        resources["OldMethod"] = {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "Api"}, "ResourceId": {"Ref": "OldResource"},
                "HttpMethod": "GET", "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "MOCK",
                    "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                    "IntegrationResponses": [{
                        "StatusCode": "200",
                        "ResponseTemplates": {
                            "application/json": {"Fn::Sub": '{"marker": "${Marker}"}'}},
                    }],
                },
                "MethodResponses": [{"StatusCode": "200"}],
            },
        }
        resources["Stage"] = {"Type": "AWS::ApiGateway::Stage",
                              "Properties": {"RestApiId": {"Ref": "Api"},
                                             "DeploymentId": {"Ref": "Deployment"},
                                             "StageName": _STAGE}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Marker": {"Type": "String"}},
        "Resources": resources,
    })


@tags(
    "axis:rejection",
    "concern:deploy",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A CloudFormation Deployment on a RestApi with no Method fails and the stack rolls back leaving no
    RestApi, while the same stack with the Method deploys and its stage serves over HTTPS."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    marker = ctx.unique_name("ctl-")
    params = [{"ParameterKey": "Marker", "ParameterValue": marker}]

    # Both stacks are launched before either is waited on, so neither outcome can be an
    # artefact of the other having finished first.
    broken_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-agwnomethod-"),
        TemplateBody=_template(with_method=False), Parameters=params,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, broken_id))
    control_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-agwctl-"),
        TemplateBody=_template(with_method=True), Parameters=params,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_id))

    # ---- positive control: the one-Method-different stack deploys and serves ----
    status = _wait_stack(cfn, control_id)
    assert status == "CREATE_COMPLETE", f"control stack settled at {status!r}"
    ctl_api = _physical_id(cfn, control_id, "Api")
    url = _apigw_url(ctx, ctl_api, _STAGE, "old")
    s, _, body = _poll_http(url, lambda st, h, t: st == 200, description="control GET /old 200")
    assert json.loads(body) == {"marker": marker}, f"control GET /old served {body!r}"

    # ---- the broken stack: Deployment rejected, whole stack rolled back ----
    status = _wait_stack(cfn, broken_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"a Deployment on a method-less RestApi left the stack at {status!r}, expected "
        f"ROLLBACK_COMPLETE"
    )
    events = _events(cfn, broken_id)
    failed = [e for e in events
              if e["LogicalResourceId"] == "Deployment" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, (
        f"expected exactly one Deployment CREATE_FAILED, got {_summary(events)!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    handler = _HANDLER_CODE.search(reason)
    assert handler is not None and handler.group(1) == "InvalidRequest", (
        f"Deployment CREATE_FAILED HandlerErrorCode was "
        f"{handler.group(1) if handler else None!r}, expected 'InvalidRequest'; reason {reason!r}"
    )
    http_status = _STATUS_CODE.search(reason)
    assert http_status is not None and http_status.group(1) == "400", (
        f"Deployment CREATE_FAILED carried API Gateway status "
        f"{http_status.group(1) if http_status else None!r}, expected '400'; reason {reason!r}"
    )
    assert "doesn't contain any methods" in reason, (
        f"Deployment failed for a reason other than the missing Method: {reason!r}"
    )
    failures = sorted({e["LogicalResourceId"] for e in events
                       if e["ResourceStatus"] == "CREATE_FAILED"})
    assert failures == ["Deployment"], (
        f"only the Deployment should fail; CREATE_FAILED resources were {failures!r}"
    )

    # Effect absent: rollback must have deleted the RestApi it had already created.
    created_api = next((e["PhysicalResourceId"] for e in events
                        if e["LogicalResourceId"] == "Api"
                        and e["ResourceStatus"] == "CREATE_COMPLETE"), None)
    assert created_api, f"the broken stack never created its RestApi: {_summary(events)!r}"
    rolled_back = [e["LogicalResourceId"] for e in events if e["ResourceStatus"] == "DELETE_COMPLETE"]
    assert {"Api", "OldResource"} <= set(rolled_back), (
        f"rollback did not delete the resources it created; DELETE_COMPLETE for {rolled_back!r}"
    )
    code = _error_code(lambda: apigw.get_rest_api(restApiId=created_api))
    assert code == "NotFoundException", (
        f"GetRestApi on the rolled-back RestApi {created_api!r} returned {code!r}, expected "
        f"NotFoundException"
    )
    assert created_api != ctl_api, "the two stacks resolved to the same RestApi"
    s, _, body = _http("GET", url)
    assert s == 200 and json.loads(body) == {"marker": marker}, (
        f"control GET /old after the broken stack rolled back returned ({s!r}, {body!r})"
    )


def _error_code(fn):
    """The AWS error code fn raised. A call that SUCCEEDS returns a sentinel no code equals."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "<call succeeded>"


def _wait_stack(cfn, stack_id, timeout_s=900.0, interval_s=5.0):
    """Poll a stack (by id, so DELETE_COMPLETE stays visible) until it is not IN_PROGRESS."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if "IN_PROGRESS" not in status:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} still in progress after {timeout_s}s "
                         f"(last {status!r})")


def _delete_stack(cfn, stack_id):
    try:
        cfn.delete_stack(StackName=stack_id)
        status = _wait_stack(cfn, stack_id)
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(
            f"stack {stack_id}: delete raised {type(exc).__name__}: {exc}"
        ) from exc
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id}: delete settled at {status}")


def _events(cfn, stack_id):
    """Every stack event, oldest first (DescribeStackEvents pages newest first)."""
    newest_first = [e for page in cfn.get_paginator("describe_stack_events").paginate(
        StackName=stack_id) for e in page["StackEvents"]]
    return list(reversed(newest_first))


def _summary(events):
    return [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events]


def _physical_id(cfn, stack_id, logical_id):
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _http(method, url):
    """(status, lowercased headers, body). A transport failure is status None, quoted."""
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())
    except urllib.error.URLError as exc:
        return None, {}, f"transport error: {exc.reason!r}"


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, timeout_s=120.0, interval_s=3.0, description="response"):
    """Re-issue GET until predicate(status, headers, text) holds; a new stage's hostname
    and snapshot become servable asynchronously."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, headers, text = _http("GET", url)
        if predicate(status, headers, text):
            return status, headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s at {url}; "
                                 f"last=({status!r}, {text!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
