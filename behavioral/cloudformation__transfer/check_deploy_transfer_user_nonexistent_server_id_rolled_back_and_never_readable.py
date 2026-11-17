"""deploy-transfer-user-nonexistent-server-id-rolled-back-and-never-readable."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-transfer-user-nonexistent-server-id-rolled-back-and-never-readable"
GROUP = "deploy"
SERVICES = ["cloudformation", "transfer"]

_STACK_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_ABSENT_SERVER_ID = "s-" + "0" * 17
_HANDLER_FAILURE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)

_TRUST_TRANSFER = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def expect_error(fn, code: str, message: str) -> None:
    """Call ``fn`` and require the exact ``(code, message)``; raise if it succeeds instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected error {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected error {(code, message)!r}, but the call succeeded: {result!r}")


def _poll_stack_status(cf, stack_id: str, deadline: float) -> str:
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after its deadline")
        time.sleep(3)


def _delete_stack_and_confirm(cf, stack_id: str, timeout_s: float = 300.0) -> None:
    try:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except cf.exceptions.ClientError as exc:
        if "does not exist" in (exc.response["Error"].get("Message") or ""):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    final = _poll_stack_status(cf, stack_id, time.monotonic() + timeout_s)
    assert final == "DELETE_COMPLETE", f"stack {stack_id} ended {final!r} instead of DELETE_COMPLETE"


def _delete_server_and_confirm(transfer, server_id: str) -> None:
    try:
        transfer.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ResourceNotFoundException":
            return
        raise


def _wait_server_online(transfer, server_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state == "ONLINE":
            return
        assert state in ("STARTING", "OFFLINE"), f"server {server_id} entered {state!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"server {server_id} still {state!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _resource_reason(cf, stack_id: str, logical_id: str, status: str) -> str:
    """The single ``ResourceStatusReason`` CloudFormation recorded for ``logical_id`` at ``status``."""
    rows = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        rows.extend(page["StackEvents"])
    matches = [
        e.get("ResourceStatusReason")
        for e in rows
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(matches) == 1, f"expected exactly one {status} event for {logical_id}, got {matches!r}"
    return matches[0]


def _without_request_id(message: str) -> str:
    """``message`` with its ``Request ID`` and ``SDK Attempt Count`` values blanked out."""
    message = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <id>", message)
    return re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)


_USER_NEVER_CREATED = ("ResourceNotFoundException", "Unknown server")


def _one_user_template(server_id: str, username: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "UserRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {"AssumeRolePolicyDocument": _TRUST_TRANSFER},
                },
                "User": {
                    "Type": "AWS::Transfer::User",
                    "Properties": {
                        "ServerId": server_id,
                        "UserName": username,
                        "Role": {"Fn::GetAtt": ["UserRole", "Arn"]},
                        "HomeDirectory": "/",
                        "HomeDirectoryType": "PATH",
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Transfer::User naming a ServerId that does not exist fails CREATE_FAILED with the
    handler's "Unknown server" NotFound reason and the stack rolls back to ROLLBACK_COMPLETE;
    the identical template naming a real server reaches CREATE_COMPLETE and the user is readable.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-transfer-user.html
    """
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")

    server_name = ctx.unique_name("sim2real-cfnsftp2-")
    server_id = transfer.create_server(
        Protocols=["SFTP"],
        EndpointType="PUBLIC",
        IdentityProviderType="SERVICE_MANAGED",
        Tags=[{"Key": "sim2real", "Value": server_name}],
    )["ServerId"]
    ctx.on_cleanup(lambda sid=server_id: _delete_server_and_confirm(transfer, sid))
    _wait_server_online(transfer, server_id)

    good_username = ctx.unique_name("sim2real-sftpok-")
    good_stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-cfntrugood-"),
        TemplateBody=_one_user_template(server_id, good_username),
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda sid=good_stack_id: _delete_stack_and_confirm(cfn, sid))
    good_status = _poll_stack_status(cfn, good_stack_id, time.monotonic() + 300.0)
    assert good_status == "CREATE_COMPLETE", f"the control stack ended {good_status!r}, expected CREATE_COMPLETE"
    described = transfer.describe_user(ServerId=server_id, UserName=good_username)["User"]
    assert described["UserName"] == good_username, (
        f"the control user reads back {described['UserName']!r}, expected {good_username!r}"
    )

    bad_username = ctx.unique_name("sim2real-sftpbad-")
    bad_stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-cfntrubad-"),
        TemplateBody=_one_user_template(_ABSENT_SERVER_ID, bad_username),
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda sid=bad_stack_id: _delete_stack_and_confirm(cfn, sid))
    bad_status = _poll_stack_status(cfn, bad_stack_id, time.monotonic() + 300.0)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"the stack naming an absent server ended {bad_status!r}, expected ROLLBACK_COMPLETE"
    )

    reason = _resource_reason(cfn, bad_stack_id, "User", "CREATE_FAILED")
    match = _HANDLER_FAILURE.match(reason)
    assert match is not None, f"the User CREATE_FAILED reason did not match the resource-handler form: {reason!r}"
    got = (_without_request_id(match["message"]), match["code"])
    want = (
        "Unknown server (Service: Transfer, Status Code: 400, Request ID: <id>) "
        "(SDK Attempt Count: <n>)",
        "NotFound",
    )
    assert got == want, f"the User CREATE_FAILED reason was {got!r}, expected {want!r}"

    expect_error(
        lambda: transfer.describe_user(ServerId=_ABSENT_SERVER_ID, UserName=bad_username),
        *_USER_NEVER_CREATED,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
