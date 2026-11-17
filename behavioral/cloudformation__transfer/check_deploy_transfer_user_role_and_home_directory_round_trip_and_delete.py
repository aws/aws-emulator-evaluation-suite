"""deploy-transfer-user-role-and-home-directory-round-trip-and-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-transfer-user-role-and-home-directory-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "transfer"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack_capped(ctx, cf, stack_id, cap_s, terminal=_TERMINAL):
    """wait_stack with its deadline capped by the run budget; a budget-ended wait is not graded."""
    try:
        return wait_stack(cf, stack_id, terminal, _budget_s(ctx, cap_s))
    except AssertionError:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"stack {stack_id} reaching a terminal status: the run budget ended first; "
                "not graded"
            ) from None
        raise


def _error(fn):
    """The AWS ``(code, message)`` ``fn()`` raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"].get("Code"), exc.response["Error"].get("Message") or "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


# ---- Check-specific: the template, then run(). ----

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _template(username: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "HomeBucket": {"Type": "AWS::S3::Bucket"},
                "UserRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": _TRUST,
                        "Policies": [
                            {
                                "PolicyName": "home-directory-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "s3:ListBucket",
                                            "Resource": {"Fn::GetAtt": ["HomeBucket", "Arn"]},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:GetObject",
                                                "s3:PutObject",
                                                "s3:DeleteObject",
                                            ],
                                            "Resource": {"Fn::Sub": "${HomeBucket.Arn}/*"},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Server": {
                    "Type": "AWS::Transfer::Server",
                    "Properties": {
                        "Protocols": ["SFTP"],
                        "EndpointType": "PUBLIC",
                        "IdentityProviderType": "SERVICE_MANAGED",
                    },
                },
                "User": {
                    "Type": "AWS::Transfer::User",
                    "Properties": {
                        "ServerId": {"Fn::GetAtt": ["Server", "ServerId"]},
                        "UserName": username,
                        "Role": {"Fn::GetAtt": ["UserRole", "Arn"]},
                        "HomeDirectory": {"Fn::Sub": "/${HomeBucket}"},
                        "HomeDirectoryType": "PATH",
                    },
                },
            },
            "Outputs": {
                "ServerId": {"Value": {"Fn::GetAtt": ["Server", "ServerId"]}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["UserRole", "Arn"]}},
                "HomeDirectory": {"Value": {"Fn::Sub": "/${HomeBucket}"}},
            },
        }
    )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Transfer::User with a role and home directory is real at Transfer:
    DescribeUser reads back its exact Arn, Role and HomeDirectory, ListUsers holds exactly it, and
    deleting the stack leaves DescribeServer and DescribeUser answering "Unknown server"."""
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfntru-")
    username = ctx.unique_name("sim2real-transfer-user-")

    stack_id = create_stack(ctx, cfn, stack, _template(username), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack_capped(ctx, cfn, stack_id, 300.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    server_id, role_arn = outputs["ServerId"], outputs["RoleArn"]
    home_directory = outputs["HomeDirectory"]

    described = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    got = (
        described["UserName"],
        described["Role"],
        described["HomeDirectory"],
        described["HomeDirectoryType"],
    )
    want = (username, role_arn, home_directory, "PATH")
    assert got == want, f"DescribeUser reads {got!r}, expected {want!r}"
    partition = role_arn.split(":")[1]
    want_arn = f"arn:{partition}:transfer:{ctx.region}:{ctx.account}:user/{server_id}/{username}"
    assert described["Arn"] == want_arn, (
        f"DescribeUser's Arn is {described['Arn']!r}, expected {want_arn!r}"
    )
    listed = _list_user_names(transfer, server_id)
    assert listed == {username}, (
        f"ListUsers on server {server_id!r} holds {listed!r} before the stack is deleted, "
        f"expected exactly {{{username!r}}}"
    )

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", "Unknown server")
    assert _error(lambda: transfer.describe_server(ServerId=server_id)) == gone, (
        f"DescribeServer on the stack's deleted server did not answer {gone!r}"
    )
    user_gone = _error(lambda: transfer.describe_user(ServerId=server_id, UserName=username))
    assert user_gone == gone, (
        f"DescribeUser on the stack's deleted user answered {user_gone!r}, expected {gone!r}"
    )


def _list_user_names(transfer, server_id):
    return {u["UserName"] for u in paginate(transfer, "list_users", "Users", ServerId=server_id)}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
