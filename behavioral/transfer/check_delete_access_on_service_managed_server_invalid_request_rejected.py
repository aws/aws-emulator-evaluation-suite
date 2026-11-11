"""delete-access-on-service-managed-server-invalid-request-rejected."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-access-on-service-managed-server-invalid-request-rejected"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAccess on a SERVICE_MANAGED server is rejected with InvalidRequestException even for a
    never-granted ExternalId, because the IdP-type check precedes any lookup; CreateUser/DeleteUser
    on the same server succeeds as the positive control."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)

    server_id = transfer.create_server(
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-sm-srv-")}],
    )["ServerId"]  # default IdentityProviderType=SERVICE_MANAGED

    def _cleanup_server():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_server)

    # Positive control: CreateUser/DeleteUser is this server type's grant analogue, so the
    # DeleteAccess rejection is specific to the IdP type. IdentityProviderType is immutable,
    # so there is no restore leg.
    username = ctx.unique_name("sim2realuser")
    _create_user_once_role_is_assumable(transfer, server_id, username, role_arn)

    def _cleanup_user():
        try:
            transfer.delete_user(ServerId=server_id, UserName=username)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_user)
    assert transfer.describe_user(ServerId=server_id, UserName=username)["User"]["UserName"] == username, (
        "positive control: CreateUser on the SERVICE_MANAGED server did not take effect"
    )
    transfer.delete_user(ServerId=server_id, UserName=username)
    user_gone_code, user_gone_message = _error(lambda: transfer.describe_user(ServerId=server_id, UserName=username))
    assert user_gone_code == "ResourceNotFoundException", (
        f"positive control: expected DeleteUser to remove the user, got describe code {user_gone_code!r}"
    )
    assert user_gone_message == "Unknown user", f"unexpected not-found message: {user_gone_message!r}"

    never_granted_external_id = _random_external_id()
    code, message = _error(
        lambda: transfer.delete_access(ServerId=server_id, ExternalId=never_granted_external_id)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == "Cannot delete access on server with IdP type: SERVICE_MANAGED", (
        f"unexpected DeleteAccess refusal message: {message!r}"
    )

    # DescribeAccess is refused for the same IdP-type reason.
    code2, message2 = _error(
        lambda: transfer.describe_access(ServerId=server_id, ExternalId=never_granted_external_id)
    )
    assert code2 == "InvalidRequestException", f"expected InvalidRequestException, got {code2!r}"
    assert message2 == "Cannot describe access on server with IdP type: SERVICE_MANAGED", (
        f"unexpected DescribeAccess refusal message: {message2!r}"
    )

    # The rejected call did not touch the server itself.
    desc = transfer.describe_server(ServerId=server_id)["Server"]
    assert desc["ServerId"] == server_id, f"expected server {server_id!r} still describable, got {desc.get('ServerId')!r}"



def _digits(n: int) -> str:
    return "".join(random.choices("0123456789", k=n))


def _random_external_id() -> str:
    return f"S-1-5-21-{_digits(9)}-{_digits(9)}-{_digits(9)}-{_digits(4)}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_user_once_role_is_assumable(transfer, server_id: str, username: str, role_arn: str) -> None:
    # A new IAM role propagates eventually, so Transfer may reject CreateUser as "not
    # assumable" for a few seconds after CreateRole returns.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

