"""deploy-apigateway-1-cfn-deployment-snapshot-ordering."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-1-cfn-deployment-snapshot-ordering"
GROUP = "deploy-apigw-snapshot-ordering"
SERVICES = ["apigateway"]

_STAGE = "prod"
_MISSING_TOKEN = "MissingAuthenticationTokenException"


def _method(resource_logical_id: str, marker_param: str) -> dict:
    return {
        "Type": "AWS::ApiGateway::Method",
        "Properties": {
            "RestApiId": {"Ref": "Api"},
            "ResourceId": {"Ref": resource_logical_id},
            "HttpMethod": "GET",
            "AuthorizationType": "NONE",
            "Integration": {
                "Type": "MOCK",
                "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                "IntegrationResponses": [{
                    "StatusCode": "200",
                    "ResponseTemplates": {
                        "application/json": {"Fn::Sub": '{"marker": "${%s}"}' % marker_param},
                    },
                }],
            },
            "MethodResponses": [{"StatusCode": "200"}],
        },
    }


def _resource(path_part: str) -> dict:
    return {
        "Type": "AWS::ApiGateway::Resource",
        "Properties": {
            "RestApiId": {"Ref": "Api"},
            "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
            "PathPart": path_part,
        },
    }


def _template(*, with_new: bool, deployment_id: str) -> str:
    """One RestApi + /old (+ /new) + a Deployment under ``deployment_id`` + Stage prod."""
    depends = ["OldMethod"] + (["NewMethod"] if with_new else [])
    resources = {
        "Api": {"Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}}},
        "OldResource": _resource("old"),
        "OldMethod": _method("OldResource", "OldMarker"),
        deployment_id: {"Type": "AWS::ApiGateway::Deployment", "DependsOn": depends,
                        "Properties": {"RestApiId": {"Ref": "Api"}}},
        "Stage": {"Type": "AWS::ApiGateway::Stage",
                  "Properties": {"RestApiId": {"Ref": "Api"},
                                 "DeploymentId": {"Ref": deployment_id},
                                 "StageName": _STAGE}},
    }
    if with_new:
        resources["NewResource"] = _resource("new")
        resources["NewMethod"] = _method("NewResource", "NewMarker")
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"OldMarker": {"Type": "String"}, "NewMarker": {"Type": "String"}},
        "Resources": resources,
        "Outputs": {"RestApiId": {"Value": {"Ref": "Api"}},
                    "StageName": {"Value": {"Ref": "Stage"}}},
    })


@tags(
    "axis:happy-path",
    "concern:deploy",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A CloudFormation-managed REST API stage serves the Deployment snapshot: a new /new route
    stays unroutable until the Deployment logical id changes; RestApiId and StageName survive.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-deployment.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    stack_name = ctx.unique_name("sim2real-behav-agwsnap-")
    old_marker = ctx.unique_name("old-")
    new_marker = ctx.unique_name("new-")
    params = [{"ParameterKey": "OldMarker", "ParameterValue": old_marker},
              {"ParameterKey": "NewMarker", "ParameterValue": new_marker}]

    # ---- create: RestApi, /old GET (MOCK), Deployment DependsOn the Method, Stage prod ----
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(with_new=False, deployment_id="DeploymentV1"),
        Parameters=params,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id, "CREATE_COMPLETE")
    assert status == "CREATE_COMPLETE", f"create settled at {status!r}, expected CREATE_COMPLETE"

    events = _events(cfn, stack_id)
    m_done = _first(events, "OldMethod", "CREATE_COMPLETE")
    d_start = _first(events, "DeploymentV1", "CREATE_IN_PROGRESS")
    d_done = _first(events, "DeploymentV1", "CREATE_COMPLETE")
    s_start = _first(events, "Stage", "CREATE_IN_PROGRESS")
    assert m_done is not None and d_start is not None, (
        f"missing events: OldMethod CREATE_COMPLETE at {m_done!r}, DeploymentV1 "
        f"CREATE_IN_PROGRESS at {d_start!r}; stream was {_summary(events)!r}"
    )
    assert m_done < d_start, (
        f"DependsOn violated: DeploymentV1 CREATE_IN_PROGRESS (event #{d_start}) did not wait "
        f"for OldMethod CREATE_COMPLETE (event #{m_done}); stream {_summary(events)!r}"
    )
    assert events[m_done]["Timestamp"] <= events[d_start]["Timestamp"], (
        f"event timestamps disagree with stream order: OldMethod CREATE_COMPLETE at "
        f"{events[m_done]['Timestamp']!r}, DeploymentV1 CREATE_IN_PROGRESS at "
        f"{events[d_start]['Timestamp']!r}"
    )
    assert d_done is not None and s_start is not None and d_done < s_start, (
        f"Stage (Ref DeploymentV1) started at event #{s_start} before DeploymentV1 completed "
        f"at #{d_done}; stream {_summary(events)!r}"
    )

    outputs = _outputs(cfn, stack_id)
    api_id = outputs["RestApiId"]
    assert outputs["StageName"] == _STAGE, f"stage output {outputs['StageName']!r} != {_STAGE!r}"
    dep_v1 = _physical_id(cfn, stack_id, "DeploymentV1")
    stage_dep_1 = apigw.get_stage(restApiId=api_id, stageName=_STAGE)["deploymentId"]
    assert stage_dep_1 == dep_v1, (
        f"stage serves deployment {stage_dep_1!r}, but the stack's DeploymentV1 is {dep_v1!r}"
    )

    old_url = _apigw_url(ctx, api_id, _STAGE, "old")
    new_url = _apigw_url(ctx, api_id, _STAGE, "new")
    status, _, body = _poll_http(old_url, lambda s, h, t: s == 200, description="GET /old 200")
    assert json.loads(body) == {"marker": old_marker}, (
        f"GET /old served {body!r}, expected the MOCK marker {old_marker!r}"
    )

    # ---- update 1: add /new + Method, KEEP the Deployment logical id ----
    seen = {e["EventId"] for e in events}
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(with_new=True, deployment_id="DeploymentV1"),
                     Parameters=params)
    status = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"update 1 settled at {status!r}, expected UPDATE_COMPLETE"
    upd1 = [e for e in _events(cfn, stack_id) if e["EventId"] not in seen]
    assert _first(upd1, "NewMethod", "CREATE_COMPLETE") is not None, (
        f"update 1 never created NewMethod; its events were {_summary(upd1)!r}"
    )
    replaced = [e["ResourceStatus"] for e in upd1 if e["LogicalResourceId"] == "DeploymentV1"
                and e["ResourceStatus"] == "CREATE_IN_PROGRESS"]
    assert not replaced, (
        f"update 1 re-created DeploymentV1 although its logical id and properties were "
        f"unchanged: {_summary(upd1)!r}"
    )
    assert _physical_id(cfn, stack_id, "DeploymentV1") == dep_v1, (
        f"DeploymentV1 physical id moved from {dep_v1!r} on an update that kept its logical id"
    )
    stage_dep_2 = apigw.get_stage(restApiId=api_id, stageName=_STAGE)["deploymentId"]
    assert stage_dep_2 == dep_v1, (
        f"stage deploymentId changed {dep_v1!r} -> {stage_dep_2!r} on update 1; no new "
        f"Deployment resource exists, so the snapshot must not move"
    )
    live_paths = sorted(r["path"] for r in _paginate(apigw, "get_resources", "items",
                                                     restApiId=api_id))
    assert "/new" in live_paths, f"live RestApi lacks /new after update 1: {live_paths!r}"

    # /new is live config but not in the deployed snapshot: the stage must keep rejecting it
    # while /old (same snapshot) keeps serving. Several rounds, each anchored by the /old 200.
    for round_no in range(4):
        o_status, _, o_body = _http("GET", old_url)
        assert o_status == 200 and json.loads(o_body) == {"marker": old_marker}, (
            f"round {round_no}: GET /old regressed to ({o_status!r}, {o_body!r})"
        )
        n_status, n_headers, n_body = _http("GET", new_url)
        assert n_status == 403, (
            f"round {round_no}: GET /new returned {n_status!r} {n_body!r} — the stage served a "
            f"route that exists only in the undeployed live config"
        )
        assert n_headers.get("x-amzn-errortype") == _MISSING_TOKEN, (
            f"round {round_no}: GET /new 403 carried x-amzn-errortype "
            f"{n_headers.get('x-amzn-errortype')!r}, expected {_MISSING_TOKEN!r}"
        )
        assert json.loads(n_body) == {"message": "Missing Authentication Token"}, (
            f"round {round_no}: GET /new 403 body was {n_body!r}"
        )

    # ---- update 2: rename the Deployment logical id -> CFN replaces it and re-points Stage ----
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(with_new=True, deployment_id="DeploymentV2"),
                     Parameters=params)
    status = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"update 2 settled at {status!r}, expected UPDATE_COMPLETE"
    outputs_2 = _outputs(cfn, stack_id)
    assert outputs_2["RestApiId"] == api_id, (
        f"RestApiId changed {api_id!r} -> {outputs_2['RestApiId']!r} on a Deployment rename"
    )
    assert outputs_2["StageName"] == _STAGE, (
        f"StageName changed to {outputs_2['StageName']!r} on a Deployment rename"
    )
    dep_v2 = _physical_id(cfn, stack_id, "DeploymentV2")
    assert dep_v2 != dep_v1, f"DeploymentV2 reused the old deployment id {dep_v1!r}"
    stage_dep_3 = apigw.get_stage(restApiId=api_id, stageName=_STAGE)["deploymentId"]
    assert stage_dep_3 == dep_v2, (
        f"stage deploymentId is {stage_dep_3!r} after update 2, expected DeploymentV2 {dep_v2!r}"
    )
    remaining = sorted(d["id"] for d in _paginate(apigw, "get_deployments", "items",
                                                  restApiId=api_id))
    assert remaining == [dep_v2], (
        f"deployments after the rename are {remaining!r}; CFN should have deleted {dep_v1!r} "
        f"and kept only {dep_v2!r}"
    )
    code = _error_code(lambda: apigw.get_deployment(restApiId=api_id, deploymentId=dep_v1))
    assert code == "NotFoundException", (
        f"GetDeployment on the replaced {dep_v1!r} returned {code!r}, expected NotFoundException"
    )

    status, _, body = _poll_http(new_url, lambda s, h, t: s == 200, timeout_s=180.0,
                                 description="GET /new 200 after the re-snapshot")
    assert json.loads(body) == {"marker": new_marker}, (
        f"GET /new served {body!r}, expected the MOCK marker {new_marker!r}"
    )
    o_status, _, o_body = _http("GET", old_url)
    assert o_status == 200 and json.loads(o_body) == {"marker": old_marker}, (
        f"GET /old after the re-snapshot returned ({o_status!r}, {o_body!r})"
    )

    # ---- delete: the RestApi must actually be gone, not just CFN-reported deleted ----
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id, "DELETE_COMPLETE")
    assert status == "DELETE_COMPLETE", f"delete settled at {status!r}, expected DELETE_COMPLETE"
    code = _error_code(lambda: apigw.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", (
        f"GetRestApi {api_id!r} after stack deletion returned {code!r}, expected NotFoundException"
    )


def _error_code(fn):
    """The AWS error code fn raised. A call that SUCCEEDS returns a sentinel no code equals."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "<call succeeded>"


def _paginate(client, op, key, **kw):
    out, position = [], None
    while True:
        page = getattr(client, op)(**kw, **({"position": position} if position else {}))
        out.extend(page.get(key, []))
        position = page.get("position")
        if not position:
            return out


def _wait_stack(cfn, stack_id, want, timeout_s=900.0, interval_s=5.0):
    """Poll a stack (by id, so DELETE_COMPLETE stays visible) to a terminal status."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == want or "IN_PROGRESS" not in status:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} did not reach {want} within {timeout_s}s "
                         f"(last {status!r})")


def _delete_stack(cfn, stack_id):
    try:
        cfn.delete_stack(StackName=stack_id)
        status = _wait_stack(cfn, stack_id, "DELETE_COMPLETE")
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


def _first(events, logical_id, status):
    for i, e in enumerate(events):
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status:
            return i
    return None


def _summary(events):
    return [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events]


def _outputs(cfn, stack_id):
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, timeout_s=120.0, interval_s=3.0, description="response"):
    """Re-issue GET until predicate(status, headers, text) holds. A (re-)deployed stage —
    and a brand-new execute-api hostname's DNS — becomes servable asynchronously."""
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
