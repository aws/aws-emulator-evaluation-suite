"""sam-serverless-api-request-authorizer-missing-identity-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-serverless-api-request-authorizer-missing-identity-rejected"
GROUP = "deploy-sam-transform"
SERVICES = ["apigateway", "cloudformation"]

_STACK_CAP_S = 600.0
_POLL_S = 2.0
_CS_CAP_S = 300.0

_CFN_WRAPPER = "Transform AWS::Serverless-2016-10-31 failed with:"
_SAM_BANNER = "Invalid Serverless Application Specification document."


def _want_reason(authorizer_name: str) -> str:
    """The exact SAM diagnostic for a REQUEST authorizer naming no Identity source."""
    return (
        f"{_CFN_WRAPPER} {_SAM_BANNER} Number of errors found: 1. Resource with id [Api] is "
        f"invalid. {authorizer_name} Authorizer must specify Identity with at least one of "
        "Headers, QueryStrings, StageVariables, or Context."
    )


def _definition_body(title: str) -> dict:
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "paths": {
            "/items": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }


def _broken_template(title: str, authorizer_name: str, fn_arn: str) -> dict:
    """A REQUEST authorizer that names no Identity source."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Api": {
                "Type": "AWS::Serverless::Api",
                "Properties": {
                    "StageName": "prod",
                    "Auth": {
                        "DefaultAuthorizer": authorizer_name,
                        "Authorizers": {
                            authorizer_name: {
                                "FunctionPayloadType": "REQUEST",
                                "FunctionArn": fn_arn,
                            }
                        },
                    },
                    "DefinitionBody": _definition_body(title),
                },
            }
        },
    }


def _control_template(title: str) -> dict:
    """The same Api, with the reserved AWS_IAM authorizer instead of the broken custom one."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Api": {
                "Type": "AWS::Serverless::Api",
                "Properties": {
                    "StageName": "prod",
                    "Auth": {"DefaultAuthorizer": "AWS_IAM"},
                    "DefinitionBody": _definition_body(title),
                },
            }
        },
        "Outputs": {"ApiId": {"Value": {"Ref": "Api"}}},
    }


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Serverless::Api REQUEST authorizer naming no Identity source fails the SAM transform
    with its own diagnostic and materialises nothing; the same Api with AWS_IAM deploys.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-api-lambdarequestauthorizer.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    broken_stack = ctx.unique_name("sim2real-sam-authid-")
    broken_title = ctx.unique_name("sim2real-sam-authid-")
    authorizer_name = "MyAuthorizer"
    fn_arn = (
        f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:"
        f"{ctx.unique_name('sim2real-sam-authid-fn-')}"
    )

    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, broken_stack))
    cfn.create_change_set(
        StackName=broken_stack, ChangeSetName="sim2real-cs", ChangeSetType="CREATE",
        TemplateBody=json.dumps(_broken_template(broken_title, authorizer_name, fn_arn)),
        Capabilities=["CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    described = _poll_change_set(cfn, broken_stack, "sim2real-cs")
    assert described["Status"] == "FAILED", (
        f"a REQUEST authorizer naming no Identity source must fail the change set; got "
        f"{described['Status']!r}"
    )
    want_reason = _want_reason(authorizer_name)
    assert described.get("StatusReason") == want_reason, (
        f"expected the SAM validator's exact diagnostic {want_reason!r}, got "
        f"{described.get('StatusReason')!r}"
    )
    assert described.get("Changes") == [], (
        f"a failed transform must plan no changes; got {described.get('Changes')!r}"
    )
    shell_status = cfn.describe_stacks(StackName=broken_stack)["Stacks"][0]["StackStatus"]
    assert shell_status == "REVIEW_IN_PROGRESS", (
        f"the shell stack must stay unmaterialised; got {shell_status!r}"
    )

    control_stack = ctx.unique_name("sim2real-sam-authid-ok-")
    control_title = ctx.unique_name("sim2real-sam-authid-ok-")
    control_id = cfn.create_stack(
        StackName=control_stack, TemplateBody=json.dumps(_control_template(control_title)),
        Capabilities=["CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_id))
    control_status, control_reason = _settle(cfn, control_id)
    assert control_status == "CREATE_COMPLETE", (
        "control: the same Api with the reserved AWS_IAM authorizer instead of the broken "
        f"custom one must deploy; got {control_status!r} ({control_reason!r})"
    )
    api_id = cfn.describe_stack_resource(
        StackName=control_id, LogicalResourceId="Api"
    )["StackResourceDetail"]["PhysicalResourceId"]
    resources = apigw.get_resources(restApiId=api_id)["items"]
    items = next((r for r in resources if r["path"] == "/items"), None)
    assert items is not None, f"no /items resource among {[r['path'] for r in resources]!r}"
    method = apigw.get_method(restApiId=api_id, resourceId=items["id"], httpMethod="GET")
    assert method["authorizationType"] == "AWS_IAM", (
        f"control: expected AWS_IAM, got {method['authorizationType']!r}"
    )


def _poll_change_set(cfn, stack_name: str, change_set_name: str) -> dict:
    """Poll a change set to CREATE_COMPLETE or FAILED against a bounded deadline."""
    deadline = time.monotonic() + _CS_CAP_S
    while True:
        described = cfn.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        if described["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return described
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"change set {change_set_name!r} on {stack_name!r} did not settle within "
                f"{_CS_CAP_S}s: {described['Status']!r}"
            )
        time.sleep(_POLL_S)


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


def _delete_stack_if_present(cfn, name: str) -> None:
    """Delete ``name`` by name (a REVIEW_IN_PROGRESS shell stack has no useful StackId)."""
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        return
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        try:
            status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"shell stack {name!r} failed to delete")
        if time.monotonic() >= deadline:
            raise AssertionError(f"shell stack {name!r} did not delete within {_STACK_CAP_S}s: {status!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
