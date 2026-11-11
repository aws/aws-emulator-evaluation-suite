"""deploy-health-check-cfn-status-behavior."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-health-check-cfn-status-behavior"
GROUP = "server-side"
SERVICES = ["route53"]


_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ResourcePath:
    Type: String
    Default: '/prod/healthy'
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Ref AWS::StackName
      EndpointConfiguration:
        Types: [REGIONAL]
  HealthyResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref Api
      ParentId: !GetAtt Api.RootResourceId
      PathPart: healthy
  HealthyMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !Ref HealthyResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: '200'
      MethodResponses:
        - StatusCode: '200'
  Deployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: HealthyMethod
    Properties:
      RestApiId: !Ref Api
  Stage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref Api
      DeploymentId: !Ref Deployment
      StageName: prod
  HealthCheck:
    Type: AWS::Route53::HealthCheck
    Properties:
      HealthCheckConfig:
        Type: HTTPS
        FullyQualifiedDomainName: !Sub "${Api}.execute-api.${AWS::Region}.amazonaws.com"
        Port: 443
        ResourcePath: !Ref ResourcePath
        RequestInterval: 10
        FailureThreshold: 1
Outputs:
  HealthCheckId:
    Value: !Ref HealthCheck
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed health check reports live checker status, and a stack update that breaks the
    monitored path bumps HealthCheckVersion and turns the checkers' observed status to failure.
    """
    stack = _deploy_cfn(ctx, _TEMPLATE, params={"ResourcePath": "/prod/healthy"})
    hc_id = stack["outputs"]["HealthCheckId"]

    route53 = ctx.client("route53")
    before = route53.get_health_check(HealthCheckId=hc_id)
    version_before = before["HealthCheck"]["HealthCheckVersion"]

    healthy_obs = _poll_health_status(ctx, hc_id, lambda status: "Success" in status)
    assert "Success" in healthy_obs

    # The target is an API this check owns: an undefined path gets a deterministic 403 "Missing
    # Authentication Token" from API Gateway, which checkers score as failure. A third-party site
    # may redirect unknown paths (3xx), which checkers score as Success.
    _update_stack(ctx, stack["stack_name"], _TEMPLATE, params={"ResourcePath": "/prod/sim2real-404-nonexistent"})

    after = route53.get_health_check(HealthCheckId=hc_id)
    version_after = after["HealthCheck"]["HealthCheckVersion"]
    assert version_after > version_before
    assert after["HealthCheck"]["HealthCheckConfig"]["ResourcePath"] == "/prod/sim2real-404-nonexistent"

    unhealthy_obs = _poll_health_status(ctx, hc_id, lambda status: "Success" not in status, timeout_s=240.0)
    assert "Success" not in unhealthy_obs


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _wait_for_stack_status(
    ctx,
    stack_name: str,
    ok_statuses: set[str],
    bad_statuses: set[str],
    timeout_s: float = 300.0,
    interval_s: float = 5.0,
) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        last_status = resp["StackStatus"]
        if last_status in ok_statuses:
            return resp
        if last_status in bad_statuses:
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last saw {last_status}")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    cfn = ctx.client("cloudformation")
    _safe(lambda: cfn.delete_stack(StackName=stack_name))
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError:
            return
        last_status = resp["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached DELETE_COMPLETE, last saw {last_status}")


def _deploy_cfn(ctx, template_body: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-r53-cfn-")
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Tags": [{"Key": "sim2real-owner", "Value": stack_name}],
    }
    if params:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    )
    resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp.get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


def _update_stack(ctx, stack_name: str, template_body: str, params: dict[str, str] | None = None) -> None:
    cfn = ctx.client("cloudformation")
    kwargs: dict[str, Any] = {"StackName": stack_name, "TemplateBody": template_body}
    if params:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()]
    cfn.update_stack(**kwargs)
    _wait_for_stack_status(
        ctx, stack_name, {"UPDATE_COMPLETE"}, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED"}
    )


def _poll_health_status(
    ctx, hc_id: str, predicate, timeout_s: float = 180.0, interval_s: float = 10.0
) -> str:
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last = "<no observations yet>"
    while time.monotonic() < deadline:
        resp = route53.get_health_check_status(HealthCheckId=hc_id)
        observations = resp.get("HealthCheckObservations", [])
        for obs in observations:
            status = obs["StatusReport"]["Status"]
            last = status
            if predicate(status):
                return status
        time.sleep(interval_s)
    raise AssertionError(f"no health check observation ever matched predicate, last saw: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
