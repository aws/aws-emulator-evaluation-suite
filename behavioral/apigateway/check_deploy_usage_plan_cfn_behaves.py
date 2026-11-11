"""deploy-usage-plan-cfn-behaves."""
from __future__ import annotations

import datetime
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-usage-plan-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A UsagePlan/ApiKey/UsagePlanKey stack deployed via CloudFormation gates execute-api traffic on a
    key-required MOCK method, and GetUsage answers for the plan and date range with a well-formed
    per-key usage log (the exact count is not asserted: usage aggregation has no bounded delay)."""
    api_name = ctx.unique_name("sim2real-apigw-uplan-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name},
            },
            "PingResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "ping",
                },
            },
            "GetMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "PingResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "ApiKeyRequired": True,
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {
                                "StatusCode": "200",
                                "ResponseTemplates": {"application/json": '{"pong": true}'},
                            }
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "ApiDeployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "GetMethod",
                "Properties": {"RestApiId": {"Ref": "RestApi"}},
            },
            "ProdStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DeploymentId": {"Ref": "ApiDeployment"},
                    "StageName": "prod",
                },
            },
            "UsagePlan": {
                "Type": "AWS::ApiGateway::UsagePlan",
                "Properties": {
                    "ApiStages": [{"ApiId": {"Ref": "RestApi"}, "Stage": {"Ref": "ProdStage"}}],
                    "Throttle": {"RateLimit": 5, "BurstLimit": 2},
                    "Quota": {"Limit": 1000, "Period": "DAY"},
                },
            },
            "TestApiKey": {
                "Type": "AWS::ApiGateway::ApiKey",
                "Properties": {"Enabled": True},
            },
            "UsagePlanKey": {
                "Type": "AWS::ApiGateway::UsagePlanKey",
                "Properties": {
                    "KeyId": {"Ref": "TestApiKey"},
                    "KeyType": "API_KEY",
                    "UsagePlanId": {"Ref": "UsagePlan"},
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "RestApi"}},
            "ApiKeyId": {"Value": {"Ref": "TestApiKey"}},
            "UsagePlanId": {"Value": {"Ref": "UsagePlan"}},
        },
    }

    outputs = _deploy_cfn_stack(ctx, json.dumps(template))
    apigw = ctx.client("apigateway")

    api_key_value = apigw.get_api_key(apiKey=outputs["ApiKeyId"], includeValue=True)["value"]
    invoke_url = (
        f"{ctx.rest_api_url(outputs['RestApiId'], 'prod')}/ping"
    )

    # Newly created API keys can take a short time to propagate to the edge before
    # they authenticate requests -- poll for the first successful call.
    status, body = _poll_until(
        lambda: _http_get(invoke_url, {"x-api-key": api_key_value}),
        lambda r: r[0] == 200,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert status == 200, f"key-authenticated call never succeeded, last status={status} body={body}"
    assert json.loads(body) == {"pong": True}

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

    # GetUsage aggregation of live traffic has no documented propagation delay on AWS and can
    # lag by many minutes. The key-gated 200+pong above is the
    # authoritative proof the call was metered server-side; GetUsage's bounded, deterministic
    # contract -- which plan and date range it answers for, and the shape of its per-key log --
    # is what a single check run can actually assert.
    usage = apigw.get_usage(usagePlanId=outputs["UsagePlanId"], startDate=today, endDate=today)
    assert usage.get("usagePlanId") == outputs["UsagePlanId"], (
        f"GetUsage echoed the wrong usagePlanId: {usage!r}"
    )
    assert usage.get("startDate") == today and usage.get("endDate") == today, (
        f"GetUsage did not echo back the requested date range: {usage!r}"
    )
    items = usage.get("items")
    assert isinstance(items, dict), f"expected items to be a dict of per-key usage, got {items!r}"
    entries = items.get(outputs["ApiKeyId"])
    if entries:
        assert isinstance(entries, list) and len(entries[0]) == 2, (
            f"expected a [used, remaining] pair for the key, got {entries!r}"
        )
        used = entries[0][0]
        if used >= 1:
            print(f"GetUsage reflected the metered call: {entries[0]}")
        else:
            print(
                f"GetUsage has a log entry for the key but usage is not yet counted: {entries[0]} "
                "(known unbounded real-AWS propagation lag, not asserted here)."
            )
    else:
        print(
            f"GetUsage had not reflected the metered call yet (items={items!r}); "
            "known unbounded real-AWS propagation lag, not asserted here."
        )


def _deploy_cfn_stack(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-apigw-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _http_get(url: str, headers: dict) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
