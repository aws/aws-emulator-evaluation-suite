"""usage-plan-missing-api-key-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "usage-plan-missing-api-key-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A key-required method deployed through CloudFormation answers 403 Forbidden without rendering
    the MOCK body to a call that omits the API key, and serves the identical call that carries
    the provisioned key."""
    api_name = ctx.unique_name("sim2real-apigw-uplan-neg-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name},
            },
            "SecureResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "secure",
                },
            },
            "GetMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "SecureResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "ApiKeyRequired": True,
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {
                                "StatusCode": "200",
                                "ResponseTemplates": {
                                    "application/json": '{"secret": "granted"}'
                                },
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
        },
    }

    outputs = _deploy_cfn_stack(ctx, json.dumps(template))
    apigw = ctx.client("apigateway")
    api_key_value = apigw.get_api_key(apiKey=outputs["ApiKeyId"], includeValue=True)["value"]
    invoke_url = (
        f"{ctx.rest_api_url(outputs['RestApiId'], 'prod')}/secure"
    )

    # Positive control: the provisioned key eventually authenticates successfully.
    status, body = _poll_until(
        lambda: _http_get(invoke_url, {"x-api-key": api_key_value}),
        lambda r: r[0] == 200,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert status == 200, f"positive control never succeeded, last status={status} body={body}"
    pos_json = json.loads(body)
    assert pos_json == {"secret": "granted"}, f"expected mock integration body, got {pos_json}"

    # Negative: the same call with the x-api-key header omitted is rejected and the
    # MOCK integration response is never rendered.
    neg_status, neg_body = _http_get(invoke_url, {})
    assert neg_status == 403, f"expected 403 Forbidden without api key, got {neg_status}: {neg_body}"
    neg_json = json.loads(neg_body)
    assert neg_json == {"message": "Forbidden"}, f"unexpected rejection body: {neg_json}"
    assert "secret" not in neg_body, "integration response leaked despite missing api key"


def _deploy_cfn_stack(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-apigw-cfn-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _http_get(url: str, headers: dict) -> tuple:
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
