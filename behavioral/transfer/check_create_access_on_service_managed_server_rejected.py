"""create-access-on-service-managed-server-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-access-on-service-managed-server-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a SERVICE_MANAGED server CreateUser succeeds, while CreateAccess with a valid role fails, on both attempts,
    with InvalidRequestException "Cannot create access on server with IdP type: SERVICE_MANAGED" and DescribeAccess
    fails with the matching "Cannot describe access" message."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)

    server_id = transfer.create_server(
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-sm-srv-")}],
    )["ServerId"]  # default IdentityProviderType=SERVICE_MANAGED
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    # Positive control: this SERVICE_MANAGED server's own grant mechanism (CreateUser, since
    # it has no directory-group concept) succeeds with this exact role, on this exact server --
    # proving the account, credentials and role are otherwise healthy, so the rejection below
    # is specific to CreateAccess/IdP-type and not "nothing works here".
    username = ctx.unique_name("sim2realuser")
    _create_user_once_role_is_assumable(transfer, server_id, username, role_arn)
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))
    assert transfer.describe_user(ServerId=server_id, UserName=username)["User"]["UserName"] == username

    external_id = "S-1-1-12-1111111111-2222222222-3333333333-1111"
    error = _client_error(
        lambda: transfer.create_access(
            ServerId=server_id,
            ExternalId=external_id,
            Role=role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory="/home",
        )
    )
    assert error == ("InvalidRequestException", "Cannot create access on server with IdP type: SERVICE_MANAGED"), error

    # Effect absent: DescribeAccess for the never-created mapping reports it does not exist
    # (rather than ListAccesses/DescribeAccess, which are themselves rejected for this IdP
    # type with the same InvalidRequestException -- confirming the server-side state was never
    # touched, since even read-back is blocked at the same precondition).
    describe_error = _client_error(lambda: transfer.describe_access(ServerId=server_id, ExternalId=external_id))
    assert describe_error == ("InvalidRequestException", "Cannot describe access on server with IdP type: SERVICE_MANAGED"), describe_error

    # Repeating the exact same rejected call is idempotent -- it does not somehow succeed on a
    # second attempt.
    error2 = _client_error(
        lambda: transfer.create_access(
            ServerId=server_id,
            ExternalId=external_id,
            Role=role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory="/home",
        )
    )
    assert error2 == ("InvalidRequestException", "Cannot create access on server with IdP type: SERVICE_MANAGED"), error2


def _create_user_once_role_is_assumable(transfer, server_id: str, username: str, role_arn: str) -> None:
    from botocore.exceptions import ClientError

    # IAM roles propagate to other services on an eventually-consistent timeline -- Transfer
    # may reject CreateUser as "not assumable" for a few seconds after CreateRole returns. Bound
    # the wait rather than sleeping unconditionally: retry until it succeeds or the deadline
    # passes, at which point a persistent failure is a real defect, not propagation lag.
    deadline = time.monotonic() + 30
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            transfer.create_user(
                ServerId=server_id,
                UserName=username,
                Role=role_arn,
                HomeDirectoryType="PATH",
                HomeDirectory="/home",
            )
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    assert last_exc is not None
    raise last_exc


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-accrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


