"""deploy-apigateway-2-update-rollback-keeps-serving-good-deployment."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-2-update-rollback-keeps-serving-good-deployment"
GROUP = "deploy-apigw-rollback"
SERVICES = ["apigateway"]

_STAGE = "sim2real"
_BAD_LOGICAL_ID = "EchoDuplicate"


def _template(marker: str, *, deployment_logical_id: str, with_bad_resource: bool) -> str:
    """RestApi -> /echo Resource -> GET MOCK Method -> Deployment -> Stage.

    Renaming the Deployment's logical id forces CloudFormation to create a NEW deployment
    snapshot and repoint the Stage at it. ``with_bad_resource`` appends a second /echo
    Resource under the same parent, DependsOn the Stage, which API Gateway rejects (409).
    """
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
                        "ResponseTemplates": {"application/json": _response_template(marker)},
                    }],
                },
                "MethodResponses": [{"StatusCode": "200"}],
            },
        },
        deployment_logical_id: {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": ["EchoMethod"],
            "Properties": {"RestApiId": {"Ref": "Api"}},
        },
        "ApiStage": {
            "Type": "AWS::ApiGateway::Stage",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "DeploymentId": {"Ref": deployment_logical_id},
                "StageName": _STAGE,
            },
        },
    }
    if with_bad_resource:
        resources[_BAD_LOGICAL_ID] = {
            "Type": "AWS::ApiGateway::Resource",
            "DependsOn": ["ApiStage"],
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                "PathPart": "echo",
            },
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _response_template(marker: str) -> str:
    return json.dumps({"marker": marker})


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A failed CloudFormation UPDATE of a live REST API repoints the stage at the original
    deployment, deletes the replacement, and the HTTPS invoke URL keeps serving marker-1.
    """
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    marker1 = ctx.unique_name("marker-1-")
    marker2 = ctx.unique_name("marker-2-")
    stack_name = ctx.unique_name("sim2real-behav-agw-urb-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(marker1, deployment_logical_id="ApiDeployment",
                               with_bad_resource=False),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_settled(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"good stack settled at {status!r}, expected CREATE_COMPLETE"

    api_id = _physical_id(cfn, stack_id, "Api")
    resource_id = _physical_id(cfn, stack_id, "EchoResource")
    good_deployment = _physical_id(cfn, stack_id, "ApiDeployment")
    url = _apigw_url(ctx, api_id, _STAGE, "echo")

    # ---- positive control: the good stack serves marker-1 over HTTPS ----
    _, _, text = _poll_http(
        url, lambda s, h, t: s == 200 and _marker(t) == marker1,
        description=f"GET {url} to serve marker-1 from the freshly created stack",
    )
    assert _marker(text) == marker1, f"good stack served {text!r}, expected marker {marker1!r}"

    # ---- the failing update ----
    before = {e["EventId"] for e in _events(cfn, stack_id)}
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(marker2, deployment_logical_id="ApiDeploymentV2",
                               with_bad_resource=True),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    status = _wait_settled(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"update adding a duplicate-PathPart resource settled at {status!r}, "
        f"expected UPDATE_ROLLBACK_COMPLETE"
    )
    update_events = [e for e in _events(cfn, stack_id) if e["EventId"] not in before]
    failed = [e["LogicalResourceId"] for e in update_events
              if e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed == [_BAD_LOGICAL_ID], (
        f"CREATE_FAILED events during the update named {failed!r}, "
        f"expected exactly [{_BAD_LOGICAL_ID!r}]"
    )
    # Before the duplicate-PathPart Resource fails, the update rewrites the MOCK response to
    # marker-2 and repoints the Stage at a new Deployment, so the rollback has work to do.
    v2_created = [e.get("PhysicalResourceId") for e in update_events
                  if e["LogicalResourceId"] == "ApiDeploymentV2"
                  and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(v2_created) == 1 and v2_created[0], (
        f"replacement deployment CREATE_COMPLETE events: {v2_created!r}, expected one with an id"
    )
    v2_deployment = v2_created[0]
    assert v2_deployment != good_deployment, (
        f"replacement deployment id {v2_deployment!r} equals the original {good_deployment!r}"
    )
    stage_updated = [e for e in update_events if e["LogicalResourceId"] == "ApiStage"
                     and e["ResourceStatus"] == "UPDATE_COMPLETE"]
    assert stage_updated, "ApiStage was never UPDATE_COMPLETE during the update; nothing was repointed"

    # ---- effect: the rollback restored the serving state ----
    stage = ag.get_stage(restApiId=api_id, stageName=_STAGE)
    assert stage["deploymentId"] == good_deployment, (
        f"after rollback the stage points at {stage['deploymentId']!r}, "
        f"expected the original deployment {good_deployment!r}"
    )
    code = _error_code(lambda: ag.get_deployment(restApiId=api_id, deploymentId=v2_deployment))
    assert code == "NotFoundException", (
        f"GetDeployment on the rolled-back replacement {v2_deployment!r} returned {code!r}, "
        f"expected NotFoundException"
    )
    ir = ag.get_integration_response(restApiId=api_id, resourceId=resource_id,
                                     httpMethod="GET", statusCode="200")
    live_template = ir.get("responseTemplates", {}).get("application/json")
    assert live_template == _response_template(marker1), (
        f"method integration response after rollback is {live_template!r}, "
        f"expected it reverted to {_response_template(marker1)!r}"
    )

    _, _, text = _poll_http(
        url, lambda s, h, t: s == 200 and _marker(t) == marker1,
        description=f"GET {url} to serve marker-1 after UPDATE_ROLLBACK_COMPLETE",
    )
    seen = []
    for _ in range(3):
        status_code, _, text = _http("GET", url)
        seen.append((status_code, _marker(text)))
    assert seen == [(200, marker1)] * 3, (
        f"stage did not keep serving marker-1 after the rollback; consecutive GETs gave {seen!r}"
    )


class _Succeeded:
    """Sentinel for a call expected to fail that did not; never equal to an error code."""

    def __repr__(self) -> str:
        return "<call unexpectedly succeeded>"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return _Succeeded()


def _marker(text):
    try:
        return json.loads(text).get("marker")
    except (TypeError, ValueError, AttributeError):
        return None


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
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
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A deployment becomes servable on its stage asynchronously, so the first touch of a
    freshly (re-)pointed stage polls to a condition with a bounded deadline."""
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


def _events(cfn, stack_id: str) -> list:
    """All stack events, oldest first."""
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return list(reversed(out))


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
