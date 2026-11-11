"""deploy-rest-api-cfn-stack-invoke-behaves."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-rest-api-cfn-stack-invoke-behaves"
GROUP = "e2e"
SERVICES = ["apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ApiName:
    Type: String
Resources:
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Ref ApiName
  HelloResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: hello
  HelloMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref HelloResource
      HttpMethod: GET
      AuthorizationType: NONE
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: "200"
            ResponseTemplates:
              application/json: '{"message": "hello-from-cfn"}'
      MethodResponses:
        - StatusCode: "200"
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: HelloMethod
    Properties:
      RestApiId: !Ref RestApi
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod
Outputs:
  RestApiId:
    Value: !Ref RestApi
  ResourceId:
    Value: !Ref HelloResource
  StageName:
    Value: !Ref ApiStage
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack of RestApi/Resource/Method/Deployment/Stage yields a stage that serves HTTP
    through its execute-api URL per the templated MOCK integration."""
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"ApiName": ctx.unique_name("sim2real-e2e-api-")},
    )
    rest_api_id = outputs["RestApiId"]
    resource_id = outputs["ResourceId"]
    stage_name = outputs["StageName"]

    apigw = ctx.client("apigateway")
    stage = apigw.get_stage(restApiId=rest_api_id, stageName=stage_name)
    assert stage["stageName"] == stage_name, (
        f"expected stage {stage_name!r}, got {stage.get('stageName')!r}"
    )
    assert stage["deploymentId"], f"expected a bound deploymentId, got {stage.get('deploymentId')!r}"

    resp = apigw.test_invoke_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )
    assert resp["status"] == 200, f"TestInvokeMethod expected 200, got {resp['status']}: {resp.get('body')}"
    body = json.loads(resp["body"])
    assert body == {"message": "hello-from-cfn"}, f"unexpected TestInvokeMethod body: {body}"

    # The terminal read: a real HTTP request through the deployed stage's execute-api
    # URL, independent of the CFN-mutating calls and of TestInvokeMethod's control-plane
    # simulation. This is what actually proves the data plane is servable.
    url = _apigw_url(ctx, rest_api_id, stage_name, "hello")
    status, text = _poll_http(
        url, lambda s, t: s == 200,
        description=f"GET {url} to serve the CFN-deployed MOCK integration",
    )
    assert status == 200, f"expected 200 from the deployed stage {url}, got {status}: {text}"
    live_body = json.loads(text)
    assert live_body == {"message": "hello-from-cfn"}, (
        f"expected the deployed stage to serve the CFN-configured MOCK response, got {live_body!r}"
    )


def _deploy_cfn(
    ctx: Any, template_body: str, parameters: dict[str, str] | None = None
) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-e2e-stack-")
    params = [
        {"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()
    ]

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, Parameters=params)
    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _apigw_url(ctx: Any, api_id: str, stage: str, path: str) -> str:
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _http_get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET")) as resp:  # noqa: S310
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_http(url: str, predicate, *, description: str, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status, text = _http_get(url)
        if predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last=({status}, {text!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
