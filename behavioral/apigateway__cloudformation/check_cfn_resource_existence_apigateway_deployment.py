"""cfn-resource-existence-apigateway-deployment."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-existence-apigateway-deployment"
GROUP = "resource-existence"
SERVICES = ["apigateway", "cloudformation"]

_PATH_PART = "widgets"
_DEPLOYMENT_DESCRIPTION = "sim2real resource-existence sweep Deployment"


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": name, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
            },
            "Resource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": _PATH_PART,
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "Resource"},
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
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "Description": _DEPLOYMENT_DESCRIPTION,
                },
            },
        },
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(cfn, stack_name: str):
    def run_undo() -> None:
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in msg:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Deployment created by CloudFormation after its one Method reads back through
    GetDeployment with the description the template set, and is gone through GetDeployment's own
    NotFoundException once the stack is deleted, with its RestApi gone through GetRestApi."""
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    stack_name = ctx.unique_name("sim2real-cfnagwdep-")
    api_name = ctx.unique_name("sim2real-cfnagwdep-restapi-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(api_name),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack settled at {status!r}, expected CREATE_COMPLETE"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    phys = {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in resources}
    api_id, deployment_id = phys["RestApi"], phys["Deployment"]

    deployment = ag.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert deployment["id"] == deployment_id, f"GetDeployment id was {deployment.get('id')!r}"
    assert deployment["description"] == _DEPLOYMENT_DESCRIPTION, (
        f"GetDeployment description was {deployment.get('description')!r}"
    )

    all_deployments = ag.get_paginator("get_deployments").paginate(restApiId=api_id)
    ids = {d["id"] for page in all_deployments for d in page["items"]}
    assert ids == {deployment_id}, f"GetDeployments ids were {sorted(ids)!r}, expected [{deployment_id!r}]"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: ag.get_deployment(restApiId=api_id, deploymentId=deployment_id))
    assert code == "NotFoundException", f"GetDeployment after delete returned {code!r}: {message!r}"
    assert message == "Invalid Deployment identifier specified", (
        f"unexpected not-found message {message!r}"
    )

    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"GetRestApi after delete returned {code!r}: {message!r}"
    want = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == want, f"GetRestApi after delete answered {message!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
