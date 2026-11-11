"""deploy-stage-with-variables-cfn-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-stage-with-variables-cfn-behaves"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Stage with stageVariables, per-method cache settings, and
    cacheClusterEnabled deployed via CloudFormation exposes the variables and cache
    TTL configuration through GetStage, and the cache cluster actually provisions."""
    api_name = ctx.unique_name("sim2real-apigw-stagevar-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": api_name},
            },
            "CachedResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "cached",
                },
            },
            "GetMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "CachedResource"},
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
                "DependsOn": "GetMethod",
                "Properties": {"RestApiId": {"Ref": "RestApi"}},
            },
            "ProdStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DeploymentId": {"Ref": "ApiDeployment"},
                    "StageName": "prod",
                    "Variables": {"envLabel": "behavioral-test"},
                    "CacheClusterEnabled": True,
                    "CacheClusterSize": "0.5",
                    "MethodSettings": [
                        {
                            "ResourcePath": "/cached",
                            "HttpMethod": "GET",
                            "CachingEnabled": True,
                            "CacheTtlInSeconds": 300,
                        }
                    ],
                },
            },
        },
        "Outputs": {"RestApiId": {"Value": {"Ref": "RestApi"}}},
    }

    outputs = _deploy_cfn_stack(ctx, json.dumps(template))
    apigw = ctx.client("apigateway")

    stage = apigw.get_stage(restApiId=outputs["RestApiId"], stageName="prod")
    assert stage["variables"] == {"envLabel": "behavioral-test"}, f"unexpected stage variables: {stage['variables']}"
    assert stage["cacheClusterEnabled"] is True, f"cacheClusterEnabled was {stage['cacheClusterEnabled']!r}, expected True"

    # CloudFormation-managed Stage.MethodSettings keys the map WITHOUT the ResourcePath's leading
    # slash ("cached/GET"), unlike PatchStage/UpdateStage-created entries which keep it.
    method_settings = stage.get("methodSettings", {}).get("cached/GET")
    assert method_settings is not None, f"no methodSettings for cached/GET: {stage.get('methodSettings')}"
    assert method_settings["cachingEnabled"] is True, f"cachingEnabled was {method_settings['cachingEnabled']!r}, expected True"
    assert method_settings["cacheTtlInSeconds"] == 300, f"cacheTtlInSeconds was {method_settings['cacheTtlInSeconds']}, expected 300"

    # Cache cluster provisioning is asynchronous; poll to its terminal status.
    status = _poll_until(
        lambda: apigw.get_stage(restApiId=outputs["RestApiId"], stageName="prod")[
            "cacheClusterStatus"
        ],
        lambda s: s in ("AVAILABLE", "NOT_AVAILABLE"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert status == "AVAILABLE", f"cache cluster never became AVAILABLE, ended in {status}"


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
    )
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
