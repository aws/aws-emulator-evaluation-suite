"""deploy-cfn-apigateway-apikey-stagekeys-round-trip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigateway-apikey-stagekeys-round-trip"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]


def _template(api_name: str, stage_name: str, key_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RestApi": {
                    "Type": "AWS::ApiGateway::RestApi",
                    "Properties": {"Name": api_name},
                },
                "Method": {
                    "Type": "AWS::ApiGateway::Method",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "ResourceId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                        "HttpMethod": "GET",
                        "AuthorizationType": "NONE",
                        "Integration": {
                            "Type": "MOCK",
                            "IntegrationResponses": [{"StatusCode": "200"}],
                            "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        },
                        "MethodResponses": [{"StatusCode": "200"}],
                    },
                },
                "Deployment": {
                    "Type": "AWS::ApiGateway::Deployment",
                    "DependsOn": "Method",
                    "Properties": {"RestApiId": {"Ref": "RestApi"}},
                },
                "Stage": {
                    "Type": "AWS::ApiGateway::Stage",
                    "Properties": {
                        "RestApiId": {"Ref": "RestApi"},
                        "DeploymentId": {"Ref": "Deployment"},
                        "StageName": stage_name,
                    },
                },
                "SimKey": {
                    "Type": "AWS::ApiGateway::ApiKey",
                    "Properties": {
                        "Name": key_name,
                        "Enabled": True,
                        "StageKeys": [
                            {"RestApiId": {"Ref": "RestApi"}, "StageName": {"Ref": "Stage"}}
                        ],
                    },
                },
            },
            "Outputs": {
                "RestApiId": {"Value": {"Ref": "RestApi"}},
                "StageNameOut": {"Value": {"Ref": "Stage"}},
                "ApiKeyRef": {"Value": {"Ref": "SimKey"}},
                "ApiKeyIdAttr": {"Value": {"Fn::GetAtt": ["SimKey", "APIKeyId"]}},
            },
        }
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(
        f"stack {stack_name} not deleted within {timeout_s}s (last status {status})"
    )


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation ApiKey's StageKeys associates it with a deployed stage: GetApiKey
    reports stageKeys as ``{restApiId}/{stageName}``, and the key is gone once the stack is
    deleted."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack_name = ctx.unique_name("sim2real-cfn-apikeystg-")
    api_name = ctx.unique_name("sim2real-cfn-apikeystg-api-")
    stage_name = "sim2real"
    key_name = ctx.unique_name("sim2real-cfn-apikeystg-key-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(api_name, stage_name, key_name),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    assert outputs["ApiKeyRef"] == outputs["ApiKeyIdAttr"], (
        f"Ref(SimKey)={outputs['ApiKeyRef']!r} and Fn::GetAtt SimKey.APIKeyId="
        f"{outputs['ApiKeyIdAttr']!r} disagree on the key id"
    )
    key_id = outputs["ApiKeyRef"]
    rest_api_id = outputs["RestApiId"]
    assert outputs["StageNameOut"] == stage_name, (
        f"Ref(Stage)={outputs['StageNameOut']!r}, expected the templated StageName {stage_name!r}"
    )

    key = apigw.get_api_key(apiKey=key_id)
    assert key["name"] == key_name, (
        f"expected name {key_name!r}, GetApiKey returned {key['name']!r}"
    )
    expected_stage_key = f"{rest_api_id}/{stage_name}"
    assert key["stageKeys"] == [expected_stage_key], (
        f"expected stageKeys {[expected_stage_key]!r}, GetApiKey returned {key['stageKeys']!r}"
    )

    _delete_stack(ctx, stack_name)
    code, message = _error(lambda: apigw.get_api_key(apiKey=key_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException after delete, got {code}: {message!r}"
    )
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
