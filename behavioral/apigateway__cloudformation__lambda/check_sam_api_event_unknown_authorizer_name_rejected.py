"""sam-api-event-unknown-authorizer-name-rejected."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sam-api-event-unknown-authorizer-name-rejected"
GROUP = "deploy-sam-transform"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_STACK_CAP_S = 600.0
_POLL_S = 2.0

_HANDLER = (
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'body': 'ok'}\n"
)

_UNKNOWN_AUTHORIZER = "NoSuchAuthorizer"


def _template(function_name: str, logical_id: str) -> dict:
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
            logical_id: {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Timeout": 10,
                    "InlineCode": _HANDLER,
                    "Events": {
                        "Bad": {
                            "Type": "Api",
                            "Properties": {
                                "RestApiId": {"Ref": "Api"},
                                "Path": "/bad",
                                "Method": "get",
                                "Auth": {"Authorizer": _UNKNOWN_AUTHORIZER},
                            },
                        },
                    },
                },
            },
        },
    }


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Api event's Auth.Authorizer naming an authorizer the Serverless::Api never declares
    fails the SAM transform with a diagnostic naming the unknown authorizer, and materialises no
    REST API.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-apifunctionauth.html
    """
    cfn = ctx.client("cloudformation")

    bad_stack = ctx.unique_name("sim2real-sam-unkauth-bad-")
    bad_function = ctx.unique_name("sim2real-sam-unkauth-")
    good_stack = ctx.unique_name("sim2real-sam-unkauth-good-")
    good_function = ctx.unique_name("sim2real-sam-unkauth-")

    bad_stack_id = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=json.dumps(_template(bad_function, "Fn")),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack_id))

    status, _ = _settle(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"an event naming an undeclared authorizer must fail the transform and roll back; got "
        f"{status!r}"
    )
    transform_reason = _transform_failure_reason(cfn, bad_stack_id)
    expected = (
        "Transform AWS::Serverless-2016-10-31 failed with: Invalid Serverless Application "
        "Specification document. Number of errors found: 1. Resource with id [Fn] is invalid. "
        "Event with id [Bad] is invalid. Unable to set Authorizer [NoSuchAuthorizer] on API "
        "method [get] for path [/bad] because the related API does not define any Authorizers."
    )
    assert transform_reason == expected, (
        f"unexpected transform failure reason; got {transform_reason!r}"
    )

    resources = cfn.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    assert resources == [], (
        f"a failed transform must materialise no resource at all; got {resources!r}"
    )

    # Positive control: the identical shape, with Auth.Authorizer pointing at AWS_IAM (a name
    # the transform resolves without a declared custom authorizer) instead of the unknown name,
    # deploys cleanly -- the rejection above is specific to the unresolved name, not to the shape.
    good_template = _template(good_function, "Fn")
    good_template["Resources"]["Fn"]["Properties"]["Events"]["Bad"]["Properties"]["Auth"][
        "Authorizer"
    ] = "AWS_IAM"
    good_stack_id = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=json.dumps(good_template),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack_id))
    good_status, good_reason = _settle(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"control: naming the resolvable AWS_IAM authorizer must deploy; got {good_status!r} "
        f"({good_reason!r})"
    )


_TRANSFORM_WRAPPER = "Transform AWS::Serverless-2016-10-31 failed with:"


def _transform_failure_reason(cfn, name: str) -> str:
    """The transform's own failure reason, before CloudFormation appends the rollback note."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        for event in page["StackEvents"]:
            reason = event.get("ResourceStatusReason") or ""
            if reason.startswith(_TRANSFORM_WRAPPER) and "Rollback requested by user" not in reason:
                return reason
    raise AssertionError(f"no stack event for {name!r} carried a transform failure reason")


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
    status, _ = _status(cfn, name)
    if status == "ROLLBACK_COMPLETE":
        cfn.delete_stack(StackName=name)
    elif status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=name)
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        current = stacks[0]["StackStatus"]
        if current == "DELETE_COMPLETE":
            return
        if current == "DELETE_FAILED":
            raise AssertionError(
                f"stack {name!r} failed to delete: {stacks[0].get('StackStatusReason')!r}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name!r} did not delete within {_STACK_CAP_S}s: {current!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
