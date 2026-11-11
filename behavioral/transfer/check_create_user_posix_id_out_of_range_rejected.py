"""create-user-posix-id-out-of-range-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-posix-id-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser rejects a PosixProfile.Uid outside 0..4294967295 with ValidationException
    instead of silently clamping it into range."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    server_id = _create_basic_server(ctx)

    bad_user = ctx.unique_name("sim2real-behav-baduser-")
    code, message = _error(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=bad_user,
            Role=role_arn,
            HomeDirectory="/",
            PosixProfile={"Uid": 99999999999, "Gid": 1000},
        )
    )
    assert code == "ValidationException", f"{code!r} for out-of-range Uid"
    assert message == (
        "1 validation error detected: Value at 'posixProfile.uid' failed to satisfy constraint: "
        "Member must have value less than or equal to 4294967295"
    ), f"unexpected out-of-range Uid message: {message!r}"

    # effect absent: the out-of-range user was never persisted
    not_found_code, not_found_message = _error(
        lambda: transfer.describe_user(ServerId=server_id, UserName=bad_user)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the rejected user to be absent, got {not_found_code!r}"
    )
    assert not_found_message == "Unknown user", f"unexpected not-found message: {not_found_message!r}"

    # positive control: an in-range PosixProfile on the very same server succeeds
    good_user = ctx.unique_name("sim2real-behav-gooduser-")
    transfer.create_user(
        ServerId=server_id,
        UserName=good_user,
        Role=role_arn,
        HomeDirectory="/",
        PosixProfile={"Uid": 1000, "Gid": 1000},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=good_user))
    described = transfer.describe_user(ServerId=server_id, UserName=good_user)
    assert described["User"]["UserName"] == good_user
    assert described["User"]["PosixProfile"]["Uid"] == 1000


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_transfer_role(ctx) -> str:
    """Create a minimal IAM role trusted by transfer.amazonaws.com for use as a Role/AccessRole."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-transfer-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_basic_server(ctx) -> str:
    """Create a minimal SERVICE_MANAGED SFTP server on the EFS domain (PosixProfile is
    only settable for EFS-domain servers) and register its cleanup."""
    transfer = ctx.client("transfer")
    resp = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        EndpointType="PUBLIC",
        Domain="EFS",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    server_id = resp["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    return server_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
