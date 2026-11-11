"""create-user-duplicate-username-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-duplicate-username-rejected"
GROUP = "representation"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second user with a UserName that already exists on the same ServerId is
    rejected with ResourceExistsException, the original user is untouched, and a distinct
    UserName on the same server still succeeds (positive control)."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    username = ctx.unique_name("sim2realdup")
    original_home = "/original-home"
    transfer.create_user(
        ServerId=server_id, UserName=username, Role=role_arn, HomeDirectoryType="PATH", HomeDirectory=original_home
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))

    code, message = _error(
        lambda: transfer.create_user(
            ServerId=server_id, UserName=username, Role=role_arn, HomeDirectoryType="PATH", HomeDirectory="/different-home"
        )
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code}"
    assert message == "User already exists", f"unexpected duplicate-user message: {message!r}"

    # Effect absent: the original user's home directory was not overwritten by the rejected call
    described = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    assert described["HomeDirectory"] == original_home

    # Positive control: a genuinely distinct UserName on the same server is accepted
    other_username = ctx.unique_name("sim2realother")
    transfer.create_user(ServerId=server_id, UserName=other_username, Role=role_arn, HomeDirectoryType="PATH", HomeDirectory="/other-home")
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=other_username))
    assert transfer.describe_user(ServerId=server_id, UserName=other_username)["User"]["UserName"] == other_username


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded with {result!r}")


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    _wait_for_role(iam, name)
    return arn


def _wait_for_role(iam, role_name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """IAM roles are eventually consistent; wait until the role is visible to reads
    before Transfer is asked to assume it, rather than assuming a fixed propagation time."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError:
            time.sleep(interval_s)
    raise AssertionError(f"IAM role {role_name} never became visible within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
