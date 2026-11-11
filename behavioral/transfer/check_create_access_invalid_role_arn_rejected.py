"""create-access-invalid-role-arn-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-invalid-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccess with a malformed Role ARN fails with InvalidRequestException "Invalid Role ARN" and, with a valid
    role, with the SERVICE_MANAGED IdP-type message; DescribeAccess after each attempt fails with "Cannot describe
    access on server with IdP type: SERVICE_MANAGED"."""
    transfer = ctx.client("transfer")
    server_id = _create_basic_server(ctx)
    bad_external_id = "S-1-1-11-1111111111"

    error = _client_error(
        lambda: transfer.create_access(
            ServerId=server_id,
            ExternalId=bad_external_id,
            Role="not-an-iam-role-arn-at-all",
            HomeDirectory="/",
        )
    )
    assert error == ("InvalidRequestException", "Invalid Role ARN"), error

    # effect absent (independent read, at the destination): no access mapping was created
    # for this ExternalId -- DescribeAccess on this IdP type fails the same
    # precondition, rather than a distinguishable ResourceNotFoundException.
    absence = _client_error(
        lambda: transfer.describe_access(ServerId=server_id, ExternalId=bad_external_id)
    )
    assert absence == ("InvalidRequestException", "Cannot describe access on server with IdP type: SERVICE_MANAGED"), absence

    # positive control: the same rejection also applies with a *well-formed* role ARN --
    # it's the server's IdP type that's disqualifying, not just the malformed role.
    role_arn = _create_transfer_role(ctx)
    good_external_id = "S-1-1-11-2222222222"
    good = _client_error(
        lambda: transfer.create_access(
            ServerId=server_id,
            ExternalId=good_external_id,
            Role=role_arn,
            HomeDirectory="/",
        )
    )
    assert good == ("InvalidRequestException", "Cannot create access on server with IdP type: SERVICE_MANAGED"), good

    # effect absent (independent read, at the destination): no access mapping was created
    # for the well-formed-role attempt either.
    good_absence = _client_error(
        lambda: transfer.describe_access(ServerId=server_id, ExternalId=good_external_id)
    )
    assert good_absence == ("InvalidRequestException", "Cannot describe access on server with IdP type: SERVICE_MANAGED"), good_absence


def _client_error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-accrole-")
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
    transfer = ctx.client("transfer")
    resp = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        EndpointType="PUBLIC",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    server_id = resp["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    return server_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
