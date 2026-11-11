"""user-create-describe-delete-404."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-create-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A server reaches ONLINE; a user is created, described and updated; then the user and the
    server are deleted and each is proven gone: read refused, unlisted, and a mutation refused.
    AWS's 'Unknown user'/'Unknown server' messages do not name the id."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)
    server_id = _create_server(ctx, transfer)
    state = _wait_server_state(transfer, server_id, {"ONLINE", "START_FAILED"})
    assert state == "ONLINE", f"expected the server to reach ONLINE before creating a user, got {state!r}"
    username = ctx.unique_name("sim2real-user-")

    _retry_role_propagation(
        lambda: transfer.create_user(
            ServerId=server_id, UserName=username, Role=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )

    def _cleanup_user():
        try:
            transfer.delete_user(ServerId=server_id, UserName=username)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_user)

    desc = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    assert desc["UserName"] == username, f"expected DescribeUser to report {username!r}, got {desc['UserName']!r}"

    home = f"/{username}-home"
    transfer.update_user(ServerId=server_id, UserName=username, HomeDirectory=home)
    updated = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    assert updated.get("HomeDirectory") == home, (
        f"expected DescribeUser to reflect HomeDirectory {home!r} after UpdateUser, got {updated.get('HomeDirectory')!r}"
    )
    assert username in _list_user_names(transfer, server_id), "expected ListUsers to hold the user before the delete"

    transfer.delete_user(ServerId=server_id, UserName=username)
    code, status, message = _error(lambda: transfer.describe_user(ServerId=server_id, UserName=username))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after DeleteUser, got {code!r}"
    assert status == 400, f"expected HTTP 400 for DescribeUser on a deleted user, got {status!r}"
    expected_message = "Unknown user"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert username not in _list_user_names(transfer, server_id), "expected ListUsers to no longer hold the deleted user"
    code, status, message = _error(
        lambda: transfer.update_user(ServerId=server_id, UserName=username, HomeDirectory=home + "2")
    )
    assert code == "ResourceNotFoundException", f"expected UpdateUser on the deleted user to be ResourceNotFoundException, got {code!r}"
    assert status == 400, f"expected HTTP 400 for UpdateUser on the deleted user, got {status!r}"
    expected_message = "Unknown user"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    assert server_id in _list_server_ids(transfer), "expected ListServers to hold the server before the delete"
    transfer.delete_server(ServerId=server_id)
    code, status, message = _poll_server_gone(transfer, server_id)
    assert code == "ResourceNotFoundException", f"expected DescribeServer on the deleted server to be ResourceNotFoundException, got {code!r}"
    assert status == 400, f"expected HTTP 400 for DescribeServer on the deleted server, got {status!r}"
    expected_message = "Unknown server"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert server_id not in _list_server_ids(transfer), "expected ListServers to no longer hold the deleted server"
    code, status, message = _error(lambda: transfer.start_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", f"expected StartServer on the deleted server to be ResourceNotFoundException, got {code!r}"
    assert status == 400, f"expected HTTP 400 for StartServer on the deleted server, got {status!r}"
    expected_message = "Unknown server"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, HTTP status, message). An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"].get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_server(ctx, transfer, **kwargs):
    server_id = transfer.create_server(
        Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )["ServerId"]

    def _cleanup():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return server_id


# A poll's bounded wait, sized from the default service-class budget; never an assertion on time.
_POLL_DEADLINE_S = 900.0


def _wait_server_state(transfer, server_id, terminal):
    """Poll DescribeServer until State is in *terminal*; raises at the deadline."""
    deadline = time.monotonic() + _POLL_DEADLINE_S
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state in terminal:
            return state
        time.sleep(5)
    raise AssertionError(f"server never reached any of {sorted(terminal)} (last state {state!r})")


def _poll_server_gone(transfer, server_id):
    """Poll DescribeServer until it raises (deletion is asynchronous); returns its (code, status, message)."""
    deadline = time.monotonic() + _POLL_DEADLINE_S
    while time.monotonic() < deadline:
        try:
            transfer.describe_server(ServerId=server_id)
        except ClientError as exc:
            return (
                exc.response["Error"].get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response["Error"].get("Message") or "",
            )
        time.sleep(5)
    raise AssertionError("DescribeServer still answered for the deleted server at the poll deadline")


def _list_user_names(transfer, server_id):
    names = set()
    for page in transfer.get_paginator("list_users").paginate(ServerId=server_id):
        names.update(u["UserName"] for u in page["Users"])
    return names


def _list_server_ids(transfer):
    ids = set()
    for page in transfer.get_paginator("list_servers").paginate():
        ids.update(srv["ServerId"] for srv in page["Servers"])
    return ids


def _create_transfer_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidRequestException", "AccessDenied", "AccessDeniedException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
