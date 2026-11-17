"""sam-api-event-auth-none-overrides-default-iam."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sam-api-event-auth-none-overrides-default-iam"
GROUP = "deploy-sam-transform"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_STACK_CAP_S = 600.0
_POLL_S = 2.0

_HANDLER = (
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'body': 'ok'}\n"
)


def _template(function_name: str) -> dict:
    """An explicit Serverless::Api with Auth.DefaultAuthorizer AWS_IAM and no DefinitionBody, and
    one Function with two Api events on it: one naming no Auth, one setting Auth.Authorizer NONE.
    """
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Api": {
                "Type": "AWS::Serverless::Api",
                "Properties": {
                    "StageName": "test",
                    "Auth": {"DefaultAuthorizer": "AWS_IAM"},
                },
            },
            "Fn": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Timeout": 10,
                    "InlineCode": _HANDLER,
                    "Events": {
                        "Secured": {
                            "Type": "Api",
                            "Properties": {
                                "RestApiId": {"Ref": "Api"},
                                "Path": "/secured",
                                "Method": "get",
                            },
                        },
                        "Open": {
                            "Type": "Api",
                            "Properties": {
                                "RestApiId": {"Ref": "Api"},
                                "Path": "/open",
                                "Method": "get",
                                "Auth": {"Authorizer": "NONE"},
                            },
                        },
                    },
                },
            },
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Serverless::Api's Auth.DefaultAuthorizer AWS_IAM covers a method whose event names no
    Auth of its own, and a sibling event's Auth.Authorizer NONE overrides it to an unauthenticated
    method -- both on the deployed methods and in the Processed template's generated security.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-apifunctionauth.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack_name = ctx.unique_name("sim2real-sam-authover-")
    function_name = ctx.unique_name("sim2real-sam-authover-")

    template = _template(function_name)
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    status, reason = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"the template must deploy; got {status!r} ({reason!r})"

    api_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]

    resources = apigw.get_resources(restApiId=api_id)["items"]
    by_path = {r["path"]: r["id"] for r in resources}
    assert "/secured" in by_path and "/open" in by_path, (
        f"expected /secured and /open resources; got {sorted(by_path)!r}"
    )

    secured = apigw.get_method(restApiId=api_id, resourceId=by_path["/secured"], httpMethod="GET")
    assert secured["authorizationType"] == "AWS_IAM", (
        "a method whose event names no Auth of its own must inherit Auth.DefaultAuthorizer; "
        f"GetMethod reported {secured['authorizationType']!r}"
    )

    opened = apigw.get_method(restApiId=api_id, resourceId=by_path["/open"], httpMethod="GET")
    assert opened["authorizationType"] == "NONE", (
        "a method whose event sets Auth.Authorizer NONE must override the inherited default; "
        f"GetMethod reported {opened['authorizationType']!r}"
    )

    processed = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    api_resource = processed["Resources"]["Api"]
    assert api_resource["Type"] == "AWS::ApiGateway::RestApi", (
        f"the Processed projection must resolve to AWS::ApiGateway::RestApi; got {api_resource['Type']!r}"
    )
    body = api_resource["Properties"]["Body"]
    secured_get = body["paths"]["/secured"]["get"]
    assert secured_get.get("security") == [{"AWS_IAM": []}], (
        "the Processed body must carry the inherited IAM security requirement on /secured; "
        f"got security={secured_get.get('security')!r}"
    )
    open_get = body["paths"]["/open"]["get"]
    assert open_get.get("security") == [{"NONE": []}], (
        "the Processed body must mark the Authorizer NONE method with the NONE security "
        f"requirement, not the inherited AWS_IAM one; got security={open_get.get('security')!r}"
    )


def _status(cfn, name: str) -> tuple:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return stack["StackStatus"], stack.get("StackStatusReason")


def _settle(cfn, name: str) -> tuple:
    """Poll ``name`` to a terminal (non-``_IN_PROGRESS``) status against a bounded deadline."""
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        status, reason = _status(cfn, name)
        if not status.endswith("IN_PROGRESS"):
            return status, reason
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name!r} did not settle within {_STACK_CAP_S}s: {status!r}")
        time.sleep(_POLL_S)


def _delete_stack(cfn, name: str) -> None:
    """Delete and wait for ``DELETE_COMPLETE``; any other end raises."""
    cfn.delete_stack(StackName=name)
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(
                f"stack {name!r} failed to delete: {stacks[0].get('StackStatusReason')!r}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name!r} did not delete within {_STACK_CAP_S}s: {status!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
