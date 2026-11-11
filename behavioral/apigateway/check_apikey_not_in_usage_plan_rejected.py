"""apikey-not-in-usage-plan-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "apikey-not-in-usage-plan-rejected"
GROUP = "server-side"
SERVICES = ["apigateway"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ApiName:
    Type: String
  UsagePlanName:
    Type: String
Resources:
  RestApi:
    Type: AWS::ApiGateway::RestApi
    Properties:
      Name: !Ref ApiName
  ProtectedResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: protected
  ProtectedMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref ProtectedResource
      HttpMethod: GET
      AuthorizationType: NONE
      ApiKeyRequired: true
      Integration:
        Type: MOCK
        RequestTemplates:
          application/json: '{"statusCode": 200}'
        IntegrationResponses:
          - StatusCode: "200"
      MethodResponses:
        - StatusCode: "200"
  ApiDeployment:
    Type: AWS::ApiGateway::Deployment
    DependsOn: ProtectedMethod
    Properties:
      RestApiId: !Ref RestApi
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod
  LinkedApiKey:
    Type: AWS::ApiGateway::ApiKey
    Properties:
      Enabled: true
  UnlinkedApiKey:
    Type: AWS::ApiGateway::ApiKey
    Properties:
      Enabled: true
  MyUsagePlan:
    Type: AWS::ApiGateway::UsagePlan
    Properties:
      UsagePlanName: !Ref UsagePlanName
      ApiStages:
        - ApiId: !Ref RestApi
          Stage: !Ref ApiStage
  LinkedUsagePlanKey:
    Type: AWS::ApiGateway::UsagePlanKey
    Properties:
      KeyId: !Ref LinkedApiKey
      KeyType: API_KEY
      UsagePlanId: !Ref MyUsagePlan
Outputs:
  RestApiId:
    Value: !Ref RestApi
  StageName:
    Value: !Ref ApiStage
  LinkedApiKeyId:
    Value: !Ref LinkedApiKey
  UnlinkedApiKeyId:
    Value: !Ref UnlinkedApiKey
"""


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A valid enabled API key not associated with any usage plan covering the stage is refused 403 on an
    ApiKeyRequired method, while a sibling key linked via UsagePlanKey on the same stage is accepted."""
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "ApiName": ctx.unique_name("sim2real-unlinked-api-"),
            "UsagePlanName": ctx.unique_name("sim2real-unlinked-plan-"),
        },
    )
    rest_api_id = outputs["RestApiId"]
    stage_name = outputs["StageName"]
    linked_key_id = outputs["LinkedApiKeyId"]
    unlinked_key_id = outputs["UnlinkedApiKeyId"]

    apigw = ctx.client("apigateway")
    linked_value = apigw.get_api_key(apiKey=linked_key_id, includeValue=True)["value"]
    unlinked_value = apigw.get_api_key(apiKey=unlinked_key_id, includeValue=True)["value"]

    url = f"{ctx.rest_api_url(rest_api_id, stage_name)}/protected"

    # Positive control: the key linked to the usage plan that covers this stage works
    # once the key<->plan association has propagated to every data-plane host (a streak of 200s).
    status, body = _poll_invoke_until(
        ctx, url, {"x-api-key": linked_value}, expected_status=200, timeout_s=300, streak=5
    )
    assert status == 200, f"linked api key never became usable: {status} {body}"

    # Negative: an equally valid, enabled key that was never linked to a usage plan for
    # this stage must be rejected -- the effect (access) stays absent.
    status2, body2 = _invoke_http_get(url, {"x-api-key": unlinked_value})
    assert status2 == 403, f"expected 403 for unlinked api key, got {status2}: {body2}"
    neg_json = json.loads(body2)
    assert neg_json == {"message": "Forbidden"}, (
        f"expected the opaque {{'message': 'Forbidden'}} body for an unlinked api key "
        f"(the response must not disclose that the key exists but lacks a plan), got {neg_json}"
    )

    # Re-confirm the positive control still succeeds after the negative call (isolation).
    status3, body3 = _invoke_http_get(url, {"x-api-key": linked_value})
    assert status3 == 200, f"linked api key regressed after negative call: {status3} {body3}"


def _deploy_cfn(
    ctx: Any, template_body: str, parameters: dict[str, str] | None = None
) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-unlinked-stack-")
    params = [
        {"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()
    ]
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, Parameters=params)

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _invoke_http_get(url: str, headers: dict[str, str]) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def _poll_invoke_until(
    ctx: Any, url: str, headers: dict[str, str], expected_status: int, timeout_s: float,
    streak: int = 1,
) -> tuple[int, str]:
    """Poll until `streak` consecutive GETs answer `expected_status`; return the last answer."""
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    status, body = None, None
    run_length = 0
    while time.monotonic() < deadline:
        status, body = _invoke_http_get(url, headers)
        run_length = run_length + 1 if status == expected_status else 0
        if run_length >= streak:
            return status, body
        time.sleep(2)
    return status, body


def _capped(ctx, seconds: float) -> float:
    """A poll timeout of `seconds`, bounded by the runner's remaining time when it has a budget."""
    left = ctx.time_left()
    return seconds if left is None else min(seconds, left)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
