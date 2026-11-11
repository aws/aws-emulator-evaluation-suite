"""cfn-resource-existence-apigateway-resource."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-existence-apigateway-resource"
GROUP = "resource-existence"
SERVICES = ["apigateway", "cloudformation"]

_PATH_PART = "widgets"


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
        },
        "Outputs": {"ResourceId": {"Value": {"Fn::GetAtt": ["Resource", "ResourceId"]}}},
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
    """A CloudFormation child Resource reads back through GetResource with the template's ParentId and
    PathPart and its Fn::GetAtt ResourceId; after the stack delete GetResource and GetRestApi both
    answer NotFoundException."""
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    stack_name = ctx.unique_name("sim2real-cfnagwres-")
    api_name = ctx.unique_name("sim2real-cfnagwres-restapi-")

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
    api_id, resource_id = phys["RestApi"], phys["Resource"]

    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")

    resource = ag.get_resource(restApiId=api_id, resourceId=resource_id)
    assert resource["id"] == resource_id, f"GetResource id was {resource.get('id')!r}"
    assert resource["parentId"] == root_id, (
        f"GetResource parentId {resource.get('parentId')!r} != the RestApi's root {root_id!r}"
    )
    assert resource["pathPart"] == _PATH_PART, f"GetResource pathPart was {resource.get('pathPart')!r}"
    assert resource["path"] == f"/{_PATH_PART}", f"GetResource path was {resource.get('path')!r}"
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    assert outputs.get("ResourceId") == resource_id, (
        f"Fn::GetAtt ResourceId output was {outputs.get('ResourceId')!r}, GetResource id {resource_id!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: ag.get_resource(restApiId=api_id, resourceId=resource_id))
    assert code == "NotFoundException", f"GetResource after delete returned {code!r}: {message!r}"
    assert message == "Invalid Resource identifier specified", f"unexpected not-found message {message!r}"

    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"GetRestApi after delete returned {code!r}: {message!r}"
    want = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == want, f"GetRestApi after delete answered {message!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
