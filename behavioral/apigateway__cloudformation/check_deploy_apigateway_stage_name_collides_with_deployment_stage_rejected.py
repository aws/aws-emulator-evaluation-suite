"""deploy-apigateway-stage-name-collides-with-deployment-stage-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-stage-name-collides-with-deployment-stage-rejected"
GROUP = "deploy-apigw-rollback"
SERVICES = ["apigateway", "cloudformation"]


def _template(deploy_stage: str, explicit_stage: str) -> str:
    """RestApi -> root GET MOCK Method -> Deployment (own StageName) -> Stage.

    The Deployment's ``StageName`` property makes CreateDeployment mint a stage of
    that name itself; the separate Stage resource names ``explicit_stage``. Equal
    names make the Stage resource collide with the stage its sibling already made.
    """
    resources = {
        "Api": {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {"Name": {"Fn::Sub": "${AWS::StackName}-api"}},
        },
        "RootMethod": {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "ResourceId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                "HttpMethod": "GET",
                "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "MOCK",
                    "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                    "IntegrationResponses": [{"StatusCode": "200"}],
                },
                "MethodResponses": [{"StatusCode": "200"}],
            },
        },
        "ApiDeployment": {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": ["RootMethod"],
            "Properties": {"RestApiId": {"Ref": "Api"}, "StageName": deploy_stage},
        },
        "ApiStage": {
            "Type": "AWS::ApiGateway::Stage",
            "DependsOn": ["ApiDeployment"],
            "Properties": {
                "RestApiId": {"Ref": "Api"},
                "DeploymentId": {"Ref": "ApiDeployment"},
                "StageName": explicit_stage,
            },
        },
    }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _wait_terminal(cfn, stack_id: str, *, budget_s: float = 500.0, poll_s: float = 5.0) -> str:
    """Poll ``DescribeStacks`` to a terminal ``*_COMPLETE``/``*_FAILED`` status."""
    deadline = time.monotonic() + budget_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id!r} still {status!r} after {budget_s}s")
        time.sleep(poll_s)


def _teardown_stack(cfn, stack_id: str):
    """Delete ``stack_id`` and wait for it to reach ``DELETE_COMPLETE``, else raise."""

    def run_teardown() -> None:
        cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + 300.0
        while True:
            try:
                status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ValidationError":
                    return
                raise
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise AssertionError(f"stack {stack_id!r} delete settled at DELETE_FAILED")
            if time.monotonic() > deadline:
                raise AssertionError(f"stack {stack_id!r} still {status!r} 300s after DeleteStack")
            time.sleep(5)

    return run_teardown


def _error(fn):
    """``(Error.Code, Error.Message)`` of the ``ClientError`` ``fn()`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


def _create_failed_reason(cfn, stack_id: str, logical_id: str) -> str:
    """The ``ResourceStatusReason`` of ``logical_id``'s ``CREATE_FAILED`` event."""
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    reasons = [
        e["ResourceStatusReason"] for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, (
        f"{logical_id!r} produced {len(reasons)} CREATE_FAILED event(s) in {stack_id!r}, expected 1"
    )
    return reasons[0]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A Stage naming the stage its sibling Deployment's StageName already created fails
    CREATE_FAILED (AlreadyExists) and rolls the stack to ROLLBACK_COMPLETE, deleting the
    RestApi; two distinct stage names reach CREATE_COMPLETE off one deployment instead.
    """
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")

    collide_stage = ctx.unique_name("sim2real-behav-collide-")
    bad_name = ctx.unique_name("sim2real-behav-agw-stg-bad-")
    ctl_name = ctx.unique_name("sim2real-behav-agw-stg-ok-")
    ctl_deploy_stage = ctx.unique_name("sim2real-behav-ctl-dep-")
    ctl_explicit_stage = ctx.unique_name("sim2real-behav-ctl-exp-")

    # Both stacks are launched before either is awaited, so the control costs no wall clock.
    bad_id = cfn.create_stack(
        StackName=bad_name,
        TemplateBody=_template(collide_stage, collide_stage),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(_teardown_stack(cfn, bad_id))
    ctl_id = cfn.create_stack(
        StackName=ctl_name,
        TemplateBody=_template(ctl_deploy_stage, ctl_explicit_stage),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(_teardown_stack(cfn, ctl_id))

    bad_status = _wait_terminal(cfn, bad_id)
    ctl_status = _wait_terminal(cfn, ctl_id)

    # ---- positive control: distinct stage names, both stages exist off one deployment ----
    assert ctl_status == "CREATE_COMPLETE", (
        f"control stack (distinct stage names) settled at {ctl_status!r}, expected CREATE_COMPLETE"
    )
    ctl_api_id = cfn.describe_stack_resource(
        StackName=ctl_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]
    ctl_deployment_id = cfn.describe_stack_resource(
        StackName=ctl_id, LogicalResourceId="ApiDeployment"
    )["StackResourceDetail"]["PhysicalResourceId"]

    ctl_implicit = ag.get_stage(restApiId=ctl_api_id, stageName=ctl_deploy_stage)
    assert ctl_implicit["deploymentId"] == ctl_deployment_id, (
        f"implicit stage {ctl_deploy_stage!r} points at deployment "
        f"{ctl_implicit['deploymentId']!r}, expected {ctl_deployment_id!r}"
    )
    ctl_explicit = ag.get_stage(restApiId=ctl_api_id, stageName=ctl_explicit_stage)
    assert ctl_explicit["deploymentId"] == ctl_deployment_id, (
        f"explicit stage {ctl_explicit_stage!r} points at deployment "
        f"{ctl_explicit['deploymentId']!r}, expected {ctl_deployment_id!r}"
    )

    # ---- the colliding stack ----
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack whose Stage names its sibling Deployment's own stage settled at "
        f"{bad_status!r}, expected ROLLBACK_COMPLETE"
    )
    bad_api_id = cfn.describe_stack_resource(
        StackName=bad_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]

    reason = _create_failed_reason(cfn, bad_id, "ApiStage")
    prefix = (
        "Resource handler returned message: "
        f'"Resource of type \'AWS::ApiGateway::Stage\' with identifier '
        f"'RestApiId: {bad_api_id} StageName: {collide_stage}' already exists.\" "
        "(RequestToken: "
    )
    suffix = ", HandlerErrorCode: AlreadyExists)"
    assert reason.startswith(prefix) and reason.endswith(suffix), (
        f"CREATE_FAILED reason was {reason!r}, expected it to start with {prefix!r} "
        f"and end with {suffix!r} (the omitted middle is CloudFormation's own request token)"
    )

    deploy_events = [
        e["ResourceStatus"] for e in cfn.describe_stack_events(StackName=bad_id)["StackEvents"]
        if e["LogicalResourceId"] == "ApiDeployment"
    ]
    assert "DELETE_COMPLETE" in deploy_events, (
        f"ApiDeployment's rollback events were {deploy_events!r}, expected a DELETE_COMPLETE"
    )

    api_code, api_message = _error(lambda: ag.get_rest_api(restApiId=bad_api_id))
    assert (api_code, api_message) == (
        "NotFoundException", f"Invalid API identifier specified {ctx.account}:{bad_api_id}"
    ), f"GetRestApi after rollback returned {(api_code, api_message)!r}"

    stage_code, stage_message = _error(
        lambda: ag.get_stage(restApiId=bad_api_id, stageName=collide_stage)
    )
    assert (stage_code, stage_message) == ("NotFoundException", "Invalid stage identifier specified"), (
        f"GetStage after rollback returned {(stage_code, stage_message)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
