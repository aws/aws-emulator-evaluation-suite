"""cfn-user-pool-user-custom-named-replacement-rejected-then-succeeds-with-new-username."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-user-custom-named-replacement-rejected-then-succeeds-with-new-username"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

_CREATE_TERMINAL = frozenset({"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
_UPDATE_TERMINAL = frozenset({
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
})
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def wait_stack(cf, stack_id, terminal, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def resource_event_reason(cf, stack_id, logical_id, resource_status):
    """The ResourceStatusReason of the most recent event for ``logical_id`` in ``resource_status``."""
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == logical_id and event["ResourceStatus"] == resource_status:
                return event.get("ResourceStatusReason") or ""
    raise AssertionError(f"no {resource_status!r} event found for {logical_id!r} on stack {stack_id}")


def physical_id(cf, stack_id, logical_id):
    detail = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns."""
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, _DELETE_TERMINAL, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _email_of(cognito, pool_id, username):
    attrs = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    return next(a["Value"] for a in attrs if a["Name"] == "email")


def _template(*, pool_logical_name: str, username: str, email: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": pool_logical_name},
            },
            "User": {
                "Type": "AWS::Cognito::UserPoolUser",
                "Properties": {
                    "UserPoolId": {"Ref": "Pool"},
                    "Username": username,
                    "MessageAction": "SUPPRESS",
                    "UserAttributes": [
                        {"Name": "email", "Value": email},
                        {"Name": "email_verified", "Value": "true"},
                    ],
                },
            },
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Updating AWS::Cognito::UserPoolUser's attributes while its Username is unchanged is
    refused because the custom name would require a replacement; the identical attribute
    change together with a new Username succeeds and replaces the user."""
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")

    pool_logical_name = ctx.unique_name("sim2real-behav-cogcnpool-")
    username_1 = ctx.unique_name("sim2real-behav-cogcnuser1-")
    username_2 = ctx.unique_name("sim2real-behav-cogcnuser2-")
    email_a = "cogcn-a@example.com"
    email_b = "cogcn-b@example.com"

    stack_name = ctx.unique_name("sim2real-behav-cogcnstack-")
    stack_id = create_stack(
        ctx, cfn, stack_name, _template(pool_logical_name=pool_logical_name, username=username_1, email=email_a)
    )
    status = wait_stack(cfn, stack_id, _CREATE_TERMINAL)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    pool_id = physical_id(cfn, stack_id, "Pool")
    assert _email_of(cognito, pool_id, username_1) == email_a, (
        f"expected the freshly created user's email to be {email_a!r}"
    )
    pid_before = physical_id(cfn, stack_id, "User")
    assert pid_before == username_1, f"expected the physical id {username_1!r}, got {pid_before!r}"

    # Same Username, new attributes: CloudFormation cannot replace a custom-named resource in place.
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(
            pool_logical_name=pool_logical_name, username=username_1, email=email_b
        ),
    )
    refused_status = wait_stack(cfn, stack_id, _UPDATE_TERMINAL)
    assert refused_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"expected the same-Username update to end UPDATE_ROLLBACK_COMPLETE, got {refused_status!r}"
    )
    refused_reason = resource_event_reason(cfn, stack_id, "User", "UPDATE_FAILED")
    expected_reason = (
        f"CloudFormation cannot update a stack when a custom-named resource requires replacing. "
        f"Rename {username_1} and update the stack again."
    )
    assert refused_reason == expected_reason, (
        f"expected the refusal reason {expected_reason!r}, got {refused_reason!r}"
    )

    pid_after_refusal = physical_id(cfn, stack_id, "User")
    assert pid_after_refusal == pid_before, (
        f"the refused update must leave the physical id at {pid_before!r}, got {pid_after_refusal!r}"
    )
    assert _email_of(cognito, pool_id, username_1) == email_a, (
        f"the refused update must leave the user's email at {email_a!r}"
    )

    # Positive control: the identical attribute edit, carrying a NEW Username, succeeds.
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(
            pool_logical_name=pool_logical_name, username=username_2, email=email_b
        ),
    )
    accepted_status = wait_stack(cfn, stack_id, _UPDATE_TERMINAL)
    assert accepted_status == "UPDATE_COMPLETE", (
        f"expected the renamed update to reach UPDATE_COMPLETE, got {accepted_status!r}"
    )

    pid_after_rename = physical_id(cfn, stack_id, "User")
    assert pid_after_rename == username_2, (
        f"expected the replaced physical id {username_2!r}, got {pid_after_rename!r}"
    )
    assert _email_of(cognito, pool_id, username_2) == email_b, (
        f"expected the new user's email to be {email_b!r}"
    )

    old_user_gone = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username_1))
    assert old_user_gone == ("UserNotFoundException", "User does not exist."), (
        f"expected the replaced user {username_1!r} gone from cognito-idp, got {old_user_gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
