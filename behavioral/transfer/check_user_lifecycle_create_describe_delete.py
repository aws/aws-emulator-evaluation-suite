"""user-lifecycle-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser is visible via DescribeUser/ListUsers; DeleteUser removes it and DescribeUser 404s."""
    tf = ctx.client("transfer")
    server_id = _create_offline_server(ctx)
    role_arn = _create_transfer_role(ctx)
    user_name = ctx.unique_name("sim2real-user-")

    _retry_role_propagation(
        lambda: tf.create_user(
            ServerId=server_id,
            UserName=user_name,
            Role=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_user(tf, server_id, user_name))

    described = tf.describe_user(ServerId=server_id, UserName=user_name)["User"]
    assert described["UserName"] == user_name, (
        f"expected DescribeUser to echo UserName {user_name!r}, got {described['UserName']!r}"
    )
    assert described["Role"] == role_arn, (
        f"expected DescribeUser Role {role_arn!r}, got {described['Role']!r}"
    )

    listed = tf.list_users(ServerId=server_id)["Users"]
    assert any(u["UserName"] == user_name for u in listed), "created user missing from ListUsers"

    tf.delete_user(ServerId=server_id, UserName=user_name)
    code, message = _error(lambda: tf.describe_user(ServerId=server_id, UserName=user_name))
    assert code == "ResourceNotFoundException", f"expected 404 after delete, got {code!r}"
    assert message == "Unknown user", f"expected message 'Unknown user', got {message!r}"

    delete_code, delete_message = _error(lambda: tf.delete_user(ServerId=server_id, UserName=user_name))
    assert delete_code == "ResourceNotFoundException", (
        f"expected a second DeleteUser on the same id to 404, got {delete_code!r}"
    )
    assert delete_message == "Unknown user", f"expected message 'Unknown user', got {delete_message!r}"


def _create_offline_server(ctx) -> str:
    tf = ctx.client("transfer")
    server_id = tf.create_server(Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]
    ctx.on_cleanup(lambda: _safe_delete_server(tf, server_id))
    return server_id


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_server(tf, server_id: str) -> None:
    try:
        tf.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_user(tf, server_id: str, user_name: str) -> None:
    try:
        tf.delete_user(ServerId=server_id, UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
