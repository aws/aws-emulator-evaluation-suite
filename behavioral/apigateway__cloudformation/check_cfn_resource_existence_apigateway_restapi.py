"""cfn-resource-existence-apigateway-restapi."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-existence-apigateway-restapi"
GROUP = "resource-existence"
SERVICES = ["apigateway", "cloudformation"]

_DESCRIPTION = "sim2real resource-existence sweep RestApi"


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Name": name,
                    "Description": _DESCRIPTION,
                    "EndpointConfiguration": {"Types": ["REGIONAL"]},
                },
            },
        },
        "Outputs": {
            "RootResourceId": {"Value": {"Fn::GetAtt": ["RestApi", "RootResourceId"]}},
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
    """A REST API deployed by CloudFormation reads back through GetRestApi with the properties and
    the RootResourceId Fn::GetAtt the template set, and is gone through GetRestApi's own
    NotFoundException once the stack is deleted."""
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    stack_name = ctx.unique_name("sim2real-cfnagwrares-")
    api_name = ctx.unique_name("sim2real-cfnagwrares-restapi-")

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

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])}
    api_id = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="RestApi"
    )["StackResourceDetail"]["PhysicalResourceId"]

    api = ag.get_rest_api(restApiId=api_id)
    assert api["name"] == api_name, f"GetRestApi name was {api.get('name')!r}, expected {api_name!r}"
    assert api["description"] == _DESCRIPTION, f"GetRestApi description was {api.get('description')!r}"
    assert api["endpointConfiguration"]["types"] == ["REGIONAL"], (
        f"GetRestApi endpointConfiguration was {api.get('endpointConfiguration')!r}"
    )

    resources = ag.get_resources(restApiId=api_id)["items"]
    root = next(r for r in resources if r["path"] == "/")
    assert root["id"] == outputs["RootResourceId"], (
        f"GetResources root id {root['id']!r} != Fn::GetAtt RootResourceId {outputs['RootResourceId']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"GetRestApi after delete returned {code!r}: {message!r}"
    assert message == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"unexpected not-found message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
