"""create-access-rejected-non-directory-server."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-rejected-non-directory-server"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccess on a SERVICE_MANAGED server fails with InvalidRequestException "Cannot create access on server with
    IdP type: SERVICE_MANAGED", and DescribeAccess on the same ExternalId fails with "Cannot describe access on server
    with IdP type: SERVICE_MANAGED", so no access mapping exists."""
    tf = ctx.client("transfer")
    server_id = _create_offline_server(ctx)
    role_arn = _create_transfer_role(ctx)
    external_id = "S-1-5-21-1111111111-2222222222-3333333333-1001"

    error = _client_error(
        lambda: tf.create_access(ServerId=server_id, ExternalId=external_id, Role=role_arn)
    )
    assert error == ("InvalidRequestException", "Cannot create access on server with IdP type: SERVICE_MANAGED"), error

    # effect absent: no access mapping was created for this external id
    describe_error = _client_error(
        lambda: tf.describe_access(ServerId=server_id, ExternalId=external_id)
    )
    assert describe_error == ("InvalidRequestException", "Cannot describe access on server with IdP type: SERVICE_MANAGED"), describe_error


def _create_offline_server(ctx) -> str:
    tf = ctx.client("transfer")
    server_id = tf.create_server(
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-access-srv-")}]
    )["ServerId"]
    ctx.on_cleanup(lambda: _safe_delete_server(tf, server_id))
    return server_id


def _create_transfer_role(ctx) -> str:
    import json
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

