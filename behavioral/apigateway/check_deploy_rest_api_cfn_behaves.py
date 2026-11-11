"""deploy-rest-api-cfn-behaves."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-rest-api-cfn-behaves"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A REST API with a MOCK integration, deployment and stage created via CloudFormation serves HTTP at
    its invoke URL after CREATE_COMPLETE, rendering the exact response template the stack configured."""
    stage_name = "test"
    api_name = ctx.unique_name("sim2real-apigw-restapi-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name},
            },
            "TestResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "test",
                },
            },
            "GetMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "TestResource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {
                                "StatusCode": "200",
                                "ResponseTemplates": {
                                    "application/json": '{"message": "ok"}'
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
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "StageName": stage_name,
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "RestApi"}},
            "ResourceId": {"Value": {"Ref": "TestResource"}},
        },
    }

    outputs = _deploy_cfn_stack(ctx, json.dumps(template))
    api_id = outputs["RestApiId"]

    url = _apigw_url(ctx, api_id, stage_name, "test")
    status, text = _poll_http(
        url,
        lambda s, _t: s == 200,
        timeout_s=150.0,
        interval_s=3.0,
        description=f"GET {url} to be served by the CFN-deployed stage",
    )
    assert status == 200, f"expected 200 from the deployed stage, got {status}: {text!r}"
    body = json.loads(text)
    assert body == {"message": "ok"}, f"unexpected MOCK integration body: {body}"


def _apigw_url(ctx, api_id: str, stage: str, path: str = "") -> str:
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _http_get(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _poll_http(url, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Re-issue an HTTP GET until predicate(status, text) holds.

    A deployment becomes servable on its stage asynchronously, so the first touch of a
    freshly deployed stage polls to a condition with a bounded deadline rather than
    asserting on the very first request."""
    deadline = time.monotonic() + timeout_s
    status, text = 0, ""
    while True:
        status, text = _http_get(url)
        if predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _deploy_cfn_stack(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-apigw-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
