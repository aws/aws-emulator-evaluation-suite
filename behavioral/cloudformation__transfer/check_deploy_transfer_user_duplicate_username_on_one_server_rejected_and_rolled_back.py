"""deploy-transfer-user-duplicate-username-on-one-server-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-transfer-user-duplicate-username-on-one-server-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account):
    """``text`` masking only Request ID, RequestToken and SDK Attempt Count."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text.replace(account, "<account>")


def handler_reason(reason, account):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account), m["code"]


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
_REJECTED = (
    "User already exists (Service: Transfer, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "AlreadyExists",
)


def _template(username: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "UserRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {"AssumeRolePolicyDocument": _TRUST},
                },
                "Server": {
                    "Type": "AWS::Transfer::Server",
                    "Properties": {
                        "Protocols": ["SFTP"],
                        "EndpointType": "PUBLIC",
                        "IdentityProviderType": "SERVICE_MANAGED",
                    },
                },
                "UserOne": {
                    "Type": "AWS::Transfer::User",
                    "Properties": {
                        "ServerId": {"Fn::GetAtt": ["Server", "ServerId"]},
                        "UserName": username,
                        "Role": {"Fn::GetAtt": ["UserRole", "Arn"]},
                        "HomeDirectory": "/sim2real-cfntru2-one",
                        "HomeDirectoryType": "PATH",
                    },
                },
                "UserTwo": {
                    "Type": "AWS::Transfer::User",
                    "DependsOn": "UserOne",
                    "Properties": {
                        "ServerId": {"Fn::GetAtt": ["Server", "ServerId"]},
                        "UserName": username,
                        "Role": {"Fn::GetAtt": ["UserRole", "Arn"]},
                        "HomeDirectory": "/sim2real-cfntru2-two",
                        "HomeDirectoryType": "PATH",
                    },
                },
            },
            "Outputs": {
                "ServerId": {"Value": {"Fn::GetAtt": ["Server", "ServerId"]}},
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second AWS::Transfer::User with a UserName already on the same ServerId fails with
    AlreadyExists and the exact "User already exists" reason after the first user is created, and
    the stack rolls back, leaving neither the server nor the first user."""
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")
    username = ctx.unique_name("sim2real-transfer-dup-")

    stack_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-cfntru2-"),
        _template(username),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_stack_capped(ctx, cfn, stack_id, 900.0)
    assert status == "ROLLBACK_COMPLETE", f"stack ended {status!r}"
    events = stack_events(cfn, stack_id)
    got = handler_reason(failed_reason(events, "UserTwo"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # UserOne exists when UserTwo fails: its one CREATE_COMPLETE row precedes UserTwo's failure.
    order = [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if (e["LogicalResourceId"], e["ResourceStatus"])
        in (("UserOne", "CREATE_COMPLETE"), ("UserTwo", "CREATE_FAILED"))
    ]
    want_order = [("UserOne", "CREATE_COMPLETE"), ("UserTwo", "CREATE_FAILED")]
    assert order == want_order, f"stack events in order {order!r}, expected {want_order!r}"

    # DescribeServer on the GetAtt the template resolved, by reading it from a CREATE_COMPLETE
    # event: the output section never populates on a rolled-back stack. The event's physical id
    # is the server's full ARN, whose last path segment is its ServerId.
    created = [
        e
        for e in events
        if e["LogicalResourceId"] == "Server" and e["ResourceStatus"] == "CREATE_COMPLETE"
    ]
    assert len(created) == 1, f"expected one Server CREATE_COMPLETE event, got {created!r}"
    server_id = created[0]["PhysicalResourceId"].rsplit("/", 1)[-1]
    gone = ("ResourceNotFoundException", "Unknown server")
    server_gone = _error(lambda: transfer.describe_server(ServerId=server_id))
    assert server_gone == gone, (
        f"DescribeServer on the rolled-back stack's server answered {server_gone!r}, "
        f"expected {gone!r}"
    )
    user_gone = _error(lambda: transfer.describe_user(ServerId=server_id, UserName=username))
    assert user_gone == gone, (
        f"DescribeUser on the rolled-back stack's first user answered {user_gone!r}, "
        f"expected {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
