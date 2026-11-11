"""deploy-usage-plan-cfn-quota-enforced."""
from __future__ import annotations

import datetime
import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-usage-plan-cfn-quota-enforced"
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
  UsageResource:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref RestApi
      ParentId: !GetAtt RestApi.RootResourceId
      PathPart: usage
  UsageMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref RestApi
      ResourceId: !Ref UsageResource
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
    DependsOn: UsageMethod
    Properties:
      RestApiId: !Ref RestApi
  ApiStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      RestApiId: !Ref RestApi
      DeploymentId: !Ref ApiDeployment
      StageName: prod
  MyApiKey:
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
      Quota:
        Limit: 3
        Period: DAY
  MyUsagePlanKey:
    Type: AWS::ApiGateway::UsagePlanKey
    Properties:
      KeyId: !Ref MyApiKey
      KeyType: API_KEY
      UsagePlanId: !Ref MyUsagePlan
Outputs:
  RestApiId:
    Value: !Ref RestApi
  StageName:
    Value: !Ref ApiStage
  UsagePlanId:
    Value: !Ref MyUsagePlan
  ApiKeyId:
    Value: !Ref MyApiKey
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-provisioned usage plan enforces its DAY quota of 3 via the invoke URL: 3 keyed requests
    succeed, the 4th gets 429 "Limit Exceeded", and GetUsage answers for the plan and date range."""
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "ApiName": ctx.unique_name("sim2real-quota-api-"),
            "UsagePlanName": ctx.unique_name("sim2real-quota-plan-"),
        },
    )
    rest_api_id = outputs["RestApiId"]
    stage_name = outputs["StageName"]
    usage_plan_id = outputs["UsagePlanId"]
    api_key_id = outputs["ApiKeyId"]

    apigw = ctx.client("apigateway")
    api_key_value = apigw.get_api_key(apiKey=api_key_id, includeValue=True)["value"]

    url = f"{ctx.rest_api_url(rest_api_id, stage_name)}/usage"
    headers = {"x-api-key": api_key_value}

    # API-key/usage-plan association can take a couple of minutes to propagate to the
    # data plane; poll until requests are actually accepted before priming the quota.
    success_count = 0
    deadline = time.monotonic() + _capped(ctx, 300)
    last_status, last_body = None, None
    while success_count < 3 and time.monotonic() < deadline:
        last_status, last_body = _invoke_http_get(url, headers)
        if last_status == 200:
            success_count += 1
        elif last_status == 403:
            time.sleep(2)
        else:
            raise AssertionError(
                f"unexpected status {last_status} while priming quota: {last_body}"
            )
    if success_count < 3:
        raise AssertionError(
            "usage-plan key never became active within 300s "
            f"(last status={last_status}, body={last_body})"
        )

    # The key/plan association is not atomic across edges, so the next call can still get a
    # transient 403 that consumes no quota; retry those. A 200 means the quota was not enforced.
    status4, body4 = None, None
    deadline4 = time.monotonic() + 120
    while time.monotonic() < deadline4:
        status4, body4 = _invoke_http_get(url, headers)
        if status4 == 429:
            break
        if status4 == 403:
            time.sleep(5)
            continue
        assert status4 != 200, (
            f"a 4th request was admitted (200) after the DAY quota of 3 was already "
            f"consumed by 3 successes -- quota was not enforced: {body4}"
        )
        raise AssertionError(
            f"unexpected status {status4} while probing for the quota rejection: {body4}"
        )
    assert status4 == 429, (
        f"expected quota-exceeded 429 within 120s of exhausting the quota, "
        f"last status={status4}: {body4}"
    )
    # A rate/burst throttle is also a bare 429; only the message body identifies quota exhaustion.
    try:
        body4_json = json.loads(body4)
    except ValueError:
        body4_json = None
    assert isinstance(body4_json, dict) and body4_json.get("message") == "Limit Exceeded", (
        "expected the quota-specific 'Limit Exceeded' message (distinct from a throttle "
        f"429's 'Too Many Requests'), got {body4!r}"
    )

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    yesterday = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    ).strftime("%Y-%m-%d")
    # GetUsage aggregation has no documented propagation SLA and can lag far beyond a bounded
    # wait, so the used count is polled opportunistically; hard asserts cover shape and scope.
    used, usage_resp = _poll_usage_for_key(
        ctx, usage_plan_id, api_key_id, yesterday, today, expected_used=3, timeout_s=120
    )
    assert usage_resp.get("usagePlanId") == usage_plan_id, (
        f"GetUsage returned wrong usagePlanId: {usage_resp!r}"
    )
    assert usage_resp.get("startDate") == yesterday and usage_resp.get("endDate") == today, (
        f"GetUsage did not echo back the requested date range: {usage_resp!r}"
    )
    entries = usage_resp.get("values", {}).get(api_key_id, [])
    # The key may be absent from `values` until AWS aggregates its first usage record, so the
    # per-day [used, remaining] shape is only asserted when present.
    assert isinstance(entries, list), f"expected a list of daily usage entries, got {entries!r}"
    assert all(isinstance(e, list) and len(e) == 2 for e in entries), (
        f"expected [used, remaining] pairs per day, got {entries!r}"
    )
    if used < 3:
        # Not a hard failure (see rationale above) -- but record it so the gap is visible.
        print(
            f"NOTE: GetUsage had not yet reflected the 3 consumed requests after 120s "
            f"(saw used={used}); this is a known real-AWS propagation lag, not a bug."
        )


def _deploy_cfn(
    ctx: Any, template_body: str, parameters: dict[str, str] | None = None
) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-quota-stack-")
    params = [
        {"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()
    ]

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=params,
        # Stack tags propagate to every taggable resource, so leftovers stay findable by tag.
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
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


def _poll_usage_for_key(
    ctx: Any,
    usage_plan_id: str,
    api_key_id: str,
    start_date: str,
    end_date: str,
    expected_used: int,
    timeout_s: float,
) -> tuple[int, dict]:
    apigw = ctx.client("apigateway")
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    used = 0
    resp: dict = {}
    while time.monotonic() < deadline:
        resp = apigw.get_usage(
            usagePlanId=usage_plan_id,
            keyId=api_key_id,
            startDate=start_date,
            endDate=end_date,
        )
        entries = resp.get("values", {}).get(api_key_id, [])
        day_total = sum(e[0] for e in entries) if entries else 0
        used = max(used, day_total)
        if used >= expected_used:
            return used, resp
        time.sleep(2)
    if not resp:
        resp = apigw.get_usage(
            usagePlanId=usage_plan_id,
            keyId=api_key_id,
            startDate=start_date,
            endDate=end_date,
        )
    return used, resp


def _capped(ctx, seconds: float) -> float:
    """A poll timeout of `seconds`, bounded by the runner's remaining time when it has a budget."""
    left = ctx.time_left()
    return seconds if left is None else min(seconds, left)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
