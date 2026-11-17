"""cfn-cognito-resource-server-and-user-stay-create-complete-after-out-of-band-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cognito-resource-server-and-user-stay-create-complete-after-out-of-band-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def wait_drift_detection(cf, detection_id, timeout_s=180.0):
    """Poll DescribeStackDriftDetectionStatus every 3 s until it leaves IN_PROGRESS."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = cf.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if result["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            return result
        if time.monotonic() > deadline:
            raise AssertionError(f"drift detection {detection_id} still in progress after {timeout_s:.0f}s")
        time.sleep(3)


def all_resource_drifts(cf, stack_id):
    """Every StackResourceDrifts row for ``stack_id``, across every page."""
    rows = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_resource_drifts(**kwargs)
        rows.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            return rows
        kwargs["NextToken"] = token


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
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=300.0)
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


def resource_status(cf, stack_id, logical_id):
    """The current ResourceStatus DescribeStackResources reports for ``logical_id``."""
    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    matches = [r for r in resources if r["LogicalResourceId"] == logical_id]
    assert len(matches) == 1, f"expected exactly one resource named {logical_id!r}, got {matches!r}"
    return matches[0]["ResourceStatus"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _template(*, pool_logical_name: str, rs_identifier: str, username: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": pool_logical_name},
            },
            "ResourceServer": {
                "Type": "AWS::Cognito::UserPoolResourceServer",
                "Properties": {
                    "UserPoolId": {"Ref": "Pool"},
                    "Identifier": rs_identifier,
                    "Name": "sim2real-behav-cogdriftrs",
                    "Scopes": [{"ScopeName": "read", "ScopeDescription": "read scope"}],
                },
            },
            "User": {
                "Type": "AWS::Cognito::UserPoolUser",
                "Properties": {
                    "UserPoolId": {"Ref": "Pool"},
                    "Username": username,
                    "MessageAction": "SUPPRESS",
                    "UserAttributes": [
                        {"Name": "email", "Value": "cogdrift@example.com"},
                        {"Name": "email_verified", "Value": "true"},
                    ],
                },
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed resource server and user keep reporting CREATE_COMPLETE after
    cognito-idp deletes their backing records directly; DetectStackDrift then finds the
    resource server DELETED but reports no drift at all for the user."""
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")

    pool_logical_name = ctx.unique_name("sim2real-behav-cogdriftpool-")
    rs_identifier = f"https://{ctx.unique_name('sim2real-behav-cogdriftrsid-')}.example.com"
    username = ctx.unique_name("sim2real-behav-cogdriftuser-")

    stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cogdriftstack-"),
        _template(pool_logical_name=pool_logical_name, rs_identifier=rs_identifier, username=username),
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    pool_id = next(r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Pool")

    # Positive control: both backing records genuinely exist right after CREATE_COMPLETE.
    rs_before = cognito.describe_resource_server(UserPoolId=pool_id, Identifier=rs_identifier)
    assert rs_before["ResourceServer"]["Identifier"] == rs_identifier, (
        f"expected the freshly created resource server, got {rs_before['ResourceServer']!r}"
    )
    user_before = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user_before["Username"] == username, (
        f"expected the freshly created user, got {user_before['Username']!r}"
    )

    # Delete both backing records directly through cognito-idp, never through CloudFormation.
    cognito.delete_resource_server(UserPoolId=pool_id, Identifier=rs_identifier)
    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)

    rs_gone = _error(lambda: cognito.describe_resource_server(UserPoolId=pool_id, Identifier=rs_identifier))
    assert rs_gone == ("ResourceNotFoundException", f"{rs_identifier} does not exist in user pool {pool_id}."), (
        f"expected the resource server gone from cognito-idp, got {rs_gone!r}"
    )
    user_gone = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert user_gone == ("UserNotFoundException", "User does not exist."), (
        f"expected the user gone from cognito-idp, got {user_gone!r}"
    )

    # CloudFormation's own view of the stack is unaware of either deletion.
    rs_status = resource_status(cfn, stack_id, "ResourceServer")
    assert rs_status == "CREATE_COMPLETE", (
        f"expected the resource server to still report CREATE_COMPLETE with no backing "
        f"record, got {rs_status!r}"
    )
    user_status = resource_status(cfn, stack_id, "User")
    assert user_status == "CREATE_COMPLETE", (
        f"expected the user to still report CREATE_COMPLETE with no backing record, "
        f"got {user_status!r}"
    )

    detection_id = cfn.detect_stack_drift(StackName=stack_id)["StackDriftDetectionId"]
    detection = wait_drift_detection(cfn, detection_id)
    assert detection["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"expected drift detection to complete, got {detection['DetectionStatus']!r}"
    )
    assert detection["StackDriftStatus"] == "DRIFTED", (
        f"expected the stack to be reported DRIFTED, got {detection['StackDriftStatus']!r}"
    )

    drifts = sorted(
        ((d["LogicalResourceId"], d["StackResourceDriftStatus"]) for d in all_resource_drifts(cfn, stack_id)),
    )
    assert drifts == [("ResourceServer", "DELETED")], (
        f"expected drift detection to report only the resource server as DELETED, with no "
        f"entry at all for the user or the pool, got {drifts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
