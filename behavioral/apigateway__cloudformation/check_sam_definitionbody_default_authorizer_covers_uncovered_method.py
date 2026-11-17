"""sam-definitionbody-default-authorizer-covers-uncovered-method."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sam-definitionbody-default-authorizer-covers-uncovered-method"
GROUP = "deploy-sam-transform"
SERVICES = ["apigateway", "cloudformation"]

_STACK_CAP_S = 600.0
_POLL_S = 2.0


def _template(title: str) -> dict:
    """A DefinitionBody-defined Serverless Api whose one method names no authorizer."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Api": {
                "Type": "AWS::Serverless::Api",
                "Properties": {
                    "StageName": "prod",
                    "Auth": {"DefaultAuthorizer": "AWS_IAM"},
                    "DefinitionBody": {
                        "swagger": "2.0",
                        "info": {"title": title, "version": "1.0"},
                        "paths": {
                            "/items": {
                                "get": {
                                    "responses": {"200": {"description": "OK"}},
                                    "x-amazon-apigateway-integration": {
                                        "type": "MOCK",
                                        "requestTemplates": {
                                            "application/json": '{"statusCode": 200}'
                                        },
                                        "responses": {"default": {"statusCode": "200"}},
                                    },
                                }
                            }
                        },
                    },
                },
            }
        },
        "Outputs": {"ApiId": {"Value": {"Ref": "Api"}}},
    }


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Serverless::Api's Auth.DefaultAuthorizer AWS_IAM covers a DefinitionBody method naming
    no authorizer of its own, both on the deployed method and in the Processed template.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack_name = ctx.unique_name("sim2real-sam-defauth-")
    title = ctx.unique_name("sim2real-sam-defauth-")

    template = _template(title)
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    status, reason = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"the DefinitionBody-defined Api with Auth.DefaultAuthorizer AWS_IAM must deploy; "
        f"got {status!r} ({reason!r})"
    )

    api_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]

    resources = apigw.get_resources(restApiId=api_id)["items"]
    items = next((r for r in resources if r["path"] == "/items"), None)
    assert items is not None, f"no /items resource among {[r['path'] for r in resources]!r}"

    method = apigw.get_method(restApiId=api_id, resourceId=items["id"], httpMethod="GET")
    assert method["authorizationType"] == "AWS_IAM", (
        "a method the DefinitionBody names no authorizer for must inherit "
        f"Auth.DefaultAuthorizer; GetMethod reported {method['authorizationType']!r}"
    )

    processed = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    api_resource = processed["Resources"]["Api"]
    assert api_resource["Type"] == "AWS::ApiGateway::RestApi", (
        "the Processed projection must resolve AWS::Serverless::Api down to "
        f"AWS::ApiGateway::RestApi; got {api_resource['Type']!r}"
    )
    body = api_resource["Properties"]["Body"]
    processed_get = body["paths"]["/items"]["get"]
    assert processed_get.get("security") == [{"AWS_IAM": []}], (
        "the Processed body must carry the inherited IAM security requirement on the "
        f"uncovered method; got security={processed_get.get('security')!r}"
    )
    assert body["securityDefinitions"]["AWS_IAM"] == {
        "type": "apiKey", "in": "header", "name": "Authorization",
        "x-amazon-apigateway-authtype": "awsSigv4",
    }, (
        f"the Processed body must declare the AWS_IAM security scheme; got "
        f"{body.get('securityDefinitions', {}).get('AWS_IAM')!r}"
    )


def _status(cfn, name: str) -> tuple[str, str | None]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return stack["StackStatus"], stack.get("StackStatusReason")


def _settle(cfn, name: str) -> tuple[str, str | None]:
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
            raise AssertionError(f"stack {name!r} failed to delete: {stacks[0].get('StackStatusReason')!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name!r} did not delete within {_STACK_CAP_S}s: {status!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
