"""deploy-apigateway-2-create-rollback-removes-rest-api."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-2-create-rollback-removes-rest-api"
GROUP = "deploy-apigw-rollback"
SERVICES = ["apigateway"]

_STAGE = "sim2real"
_BAD_LOGICAL_ID = "EchoDuplicate"


def _template(marker: str, *, with_bad_resource: bool) -> str:
    """RestApi -> /echo Resource -> GET MOCK Method -> Deployment -> Stage.

    With ``with_bad_resource`` a SECOND /echo Resource under the same parent is appended,
    DependsOn the Stage so the whole good graph is created first. API Gateway rejects it
    at create time (409 "Another resource with the same parent already has this name").
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation CREATE whose last resource API Gateway rejects rolls back the whole REST
    API (GetRestApi is NotFoundException, no API with its name remains); the same template minus
    the bad resource reaches CREATE_COMPLETE and its API is found by the same queries.
    """
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    marker = ctx.unique_name("marker-1-")

    bad_name = ctx.unique_name("sim2real-behav-agw-rb-")
    ctl_name = ctx.unique_name("sim2real-behav-agw-ok-")

    # Both stacks are launched before either is awaited, so the control costs no wall clock.
    bad_id = cfn.create_stack(
        StackName=bad_name,
        TemplateBody=_template(marker, with_bad_resource=True),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_id))
    ctl_id = cfn.create_stack(
        StackName=ctl_name,
        TemplateBody=_template(marker, with_bad_resource=False),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, ctl_id))

    bad_status = _wait_settled(cfn, bad_id)
    ctl_status = _wait_settled(cfn, ctl_id)

    # ---- positive control: the same graph without the bad resource is a working API ----
    assert ctl_status == "CREATE_COMPLETE", (
        f"control stack (no bad resource) settled at {ctl_status!r}, expected CREATE_COMPLETE"
    )
    ctl_api_id = cfn.describe_stack_resource(
        StackName=ctl_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]
    ctl_api = ag.get_rest_api(restApiId=ctl_api_id)
    assert ctl_api["name"] == f"{ctl_name}-api", (
        f"control GetRestApi returned name {ctl_api.get('name')!r}, expected {ctl_name + '-api'!r}"
    )
    ctl_hits = _rest_api_ids_named(ag, f"{ctl_name}-api")
    assert ctl_hits == [ctl_api_id], (
        f"GetRestApis name search for the control stack returned {ctl_hits!r}, "
        f"expected exactly [{ctl_api_id!r}]"
    )

    # ---- the failing stack ----
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack with a duplicate-PathPart resource settled at {bad_status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )
    events = _events(cfn, bad_id)
    failed = [e["LogicalResourceId"] for e in events
              if e["ResourceStatus"] == "CREATE_FAILED" and e["LogicalResourceId"] != bad_name]
    assert failed == [_BAD_LOGICAL_ID], (
        f"CREATE_FAILED resource events named {failed!r}, expected exactly [{_BAD_LOGICAL_ID!r}]"
    )

    completed = {e["LogicalResourceId"]: e.get("PhysicalResourceId") for e in events
                 if e["ResourceStatus"] == "CREATE_COMPLETE"}
    for logical in ("Api", "EchoResource", "EchoMethod", "ApiDeployment", "ApiStage"):
        assert completed.get(logical), (
            f"{logical} never reached CREATE_COMPLETE before the failure; the rollback would "
            f"have nothing to undo (CREATE_COMPLETE events: {sorted(completed)!r})"
        )
    api_id = completed["Api"]

    # Effect: the RestApi that really existed mid-create is gone from API Gateway.
    err = _error(lambda: ag.get_rest_api(restApiId=api_id))
    expected = ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{api_id}")
    assert err == expected, (
        f"GetRestApi({api_id!r}) after ROLLBACK_COMPLETE returned {err!r}, expected {expected!r}"
    )
    leftover = _rest_api_ids_named(ag, f"{bad_name}-api")
    assert leftover == [], (
        f"GetRestApis still lists APIs named {bad_name + '-api'!r} after rollback: {leftover!r}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _rest_api_ids_named(ag, name: str) -> list:
    ids = []
    for page in ag.get_paginator("get_rest_apis").paginate():
        ids.extend(item["id"] for item in page.get("items", []) if item.get("name") == name)
    return sorted(ids)


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
