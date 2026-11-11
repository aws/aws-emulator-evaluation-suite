"""access-create-on-service-managed-server-invalid-request-rejected."""
from __future__ import annotations

import json
import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-create-on-service-managed-server-invalid-request-rejected"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccess on a SERVICE_MANAGED server fails with InvalidRequestException "Cannot create access on server
    with IdP type: SERVICE_MANAGED", and DescribeAccess on the same ExternalId fails with "Cannot describe access
    on server with IdP type: SERVICE_MANAGED", so no access exists."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)
    server_id = transfer.create_server()["ServerId"]  # default IdentityProviderType=SERVICE_MANAGED

    def _cleanup_server():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_server)

    external_id = _random_external_id()
    code, message = _error_code(
        lambda: transfer.create_access(ServerId=server_id, ExternalId=external_id, Role=role_arn)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Cannot create access on server with IdP type: SERVICE_MANAGED", message

    # Effect absent: no Access was actually created by the rejected call. DescribeAccess on
    # this SERVICE_MANAGED server rejects with the same InvalidRequestException for the same
    # reason (Access is a directory-backed concept the server type doesn't support at all).
    code2, message2 = _error_code(lambda: transfer.describe_access(ServerId=server_id, ExternalId=external_id))
    assert code2 == "InvalidRequestException", f"expected InvalidRequestException, got {code2}"
    assert message2 == "Cannot describe access on server with IdP type: SERVICE_MANAGED", message2


def _digits(n: int) -> str:
    return "".join(random.choices("0123456789", k=n))


def _random_external_id() -> str:
    return f"S-1-5-21-{_digits(9)}-{_digits(9)}-{_digits(9)}-{_digits(4)}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

