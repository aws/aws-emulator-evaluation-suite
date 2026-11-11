"""deploy-apigateway-stage-resource-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-stage-resource-round-trip"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ApiGateway::Stage is readable through GetStage with
    the Description and Variables the template set, and GetStage and GetRestApi fail
    NotFoundException once the stack that created them is deleted."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack_name = ctx.unique_name("sim2real-cfn-stage-")
    description = ctx.unique_name("sim2real-stage-desc-")
    var_value = ctx.unique_name("sim2real-stage-var-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Name": ctx.unique_name("sim2real-stage-api-"),
                    "EndpointConfiguration": {"Types": ["REGIONAL"]},
                },
            },
            "EchoResource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "echo",
                },
            },
            "EchoMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "EchoResource"},
                    "HttpMethod": "GET",
                    # SigV4-only: the stage serves no anonymous caller.
                    "AuthorizationType": "AWS_IAM",
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
                "DependsOn": "EchoMethod",
                "Properties": {"RestApiId": {"Ref": "RestApi"}},
            },
            "EchoStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DeploymentId": {"Ref": "ApiDeployment"},
                    "StageName": "sim2real",
                    "Description": description,
                    "Variables": {"envLabel": var_value},
                },
            },
        },
        "Outputs": {
            "RestApiId": {"Value": {"Ref": "RestApi"}},
            "StageNameRef": {"Value": {"Ref": "EchoStage"}},
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    # Ref on a Stage returns its StageName.
    assert outputs["StageNameRef"] == "sim2real", (
        f"Ref(EchoStage) was {outputs['StageNameRef']!r}, expected the StageName 'sim2real'"
    )

    stage = apigw.get_stage(restApiId=outputs["RestApiId"], stageName="sim2real")
    assert stage["stageName"] == "sim2real", f"GetStage stageName was {stage['stageName']!r}"
    assert stage["description"] == description, (
        f"expected description {description!r}, GetStage returned {stage['description']!r}"
    )
    assert stage["variables"] == {"envLabel": var_value}, (
        f"expected variables {{'envLabel': {var_value!r}}}, GetStage returned {stage['variables']!r}"
    )

    # Graded in-band teardown: delete the stack and confirm the Stage is genuinely gone,
    # not merely reported deleted by CloudFormation.
    _delete_stack(ctx, stack_name)
    code, message = _error(
        lambda: apigw.get_stage(restApiId=outputs["RestApiId"], stageName="sim2real")
    )
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}: {message!r}"
    assert message == "Invalid stage identifier specified", f"unexpected message {message!r}"
    api_id = outputs["RestApiId"]
    code, message = _error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"GetRestApi after delete returned {code!r}: {message!r}"
    want = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == want, f"GetRestApi after delete answered {message!r}, expected {want!r}"


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
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
