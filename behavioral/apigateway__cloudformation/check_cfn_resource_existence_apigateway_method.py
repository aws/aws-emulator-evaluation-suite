"""cfn-resource-existence-apigateway-method."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-existence-apigateway-method"
GROUP = "resource-existence"
SERVICES = ["apigateway", "cloudformation"]

_PATH_PART = "widgets"
_REQUEST_TEMPLATE = '{"statusCode": 200}'
_RESPONSE_TEMPLATE = '{"message": "ok"}'


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
                        "RequestTemplates": {"application/json": _REQUEST_TEMPLATE},
                        "IntegrationResponses": [
                            {"StatusCode": "200",
                             "ResponseTemplates": {"application/json": _RESPONSE_TEMPLATE}},
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
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
    """A CloudFormation GET Method with a MOCK integration reads back through GetMethod with the
    template's integration and method responses; after the stack delete GetMethod and GetRestApi
    both answer NotFoundException."""
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    stack_name = ctx.unique_name("sim2real-cfnagwmeth-")
    api_name = ctx.unique_name("sim2real-cfnagwmeth-restapi-")

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

    method = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert method["httpMethod"] == "GET", f"GetMethod httpMethod was {method.get('httpMethod')!r}"
    assert method["authorizationType"] == "NONE", (
        f"GetMethod authorizationType was {method.get('authorizationType')!r}"
    )
    integration = method["methodIntegration"]
    assert integration["type"] == "MOCK", f"GetMethod integration type was {integration.get('type')!r}"
    assert integration["requestTemplates"] == {"application/json": _REQUEST_TEMPLATE}, (
        f"GetMethod integration requestTemplates were {integration.get('requestTemplates')!r}"
    )
    responses = integration["integrationResponses"]
    assert set(responses) == {"200"}, f"integrationResponses keys were {sorted(responses)!r}"
    assert responses["200"]["responseTemplates"] == {"application/json": _RESPONSE_TEMPLATE}, (
        f"integrationResponses['200'].responseTemplates were {responses['200'].get('responseTemplates')!r}"
    )
    assert set(method["methodResponses"]) == {"200"}, (
        f"GetMethod methodResponses keys were {sorted(method['methodResponses'])!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(
        lambda: ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert code == "NotFoundException", f"GetMethod after delete returned {code!r}: {message!r}"
    assert message == "Invalid Resource identifier specified", f"unexpected not-found message {message!r}"

    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"GetRestApi after delete returned {code!r}: {message!r}"
    want = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == want, f"GetRestApi after delete answered {message!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
