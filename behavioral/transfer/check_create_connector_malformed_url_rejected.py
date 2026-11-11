"""create-connector-malformed-url-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connector-malformed-url-rejected"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnector rejects an SFTP connector Url that is missing a scheme
    (e.g. "ftp.example.com" instead of "sftp://ftp.example.com") with InvalidRequestException,
    and never creates the connector."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    secret_arn = _create_dummy_secret(ctx)

    before_ids = _connector_ids(transfer)

    error = _client_error(
        lambda: transfer.create_connector(
            Url="ftp.example.com",  # missing scheme
            AccessRole=role_arn,
            SftpConfig={"UserSecretId": secret_arn},
        )
    )
    assert error == ("InvalidRequestException", "Invalid URL; Configured protocol does not support path information in the url"), error

    # effect absent: no connector was created as a side effect of the rejected call
    after_ids = _connector_ids(transfer)
    created = _own_connectors(transfer, after_ids - before_ids, role_arn)
    assert created == [], f"a connector was created despite the malformed Url: {created}"

    # positive control: the identical configuration with a well-formed Url succeeds
    good = transfer.create_connector(
        Url="sftp://ftp.example.com",
        AccessRole=role_arn,
        SftpConfig={"UserSecretId": secret_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    connector_id = good["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))
    described = transfer.describe_connector(ConnectorId=connector_id)
    actual_url = described["Connector"]["Url"]
    assert actual_url == "sftp://ftp.example.com", f"expected Url 'sftp://ftp.example.com', got {actual_url!r}"


def _client_error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected but it succeeded: {result!r}")


def _connector_ids(transfer) -> set[str]:
    ids: set[str] = set()
    paginator = transfer.get_paginator("list_connectors")
    for page in paginator.paginate():
        for connector in page.get("Connectors", []):
            ids.add(connector["ConnectorId"])
    return ids


def _own_connectors(transfer, ids, role_arn) -> list[str]:
    """The connectors among ids whose AccessRole is role_arn; one already deleted is not this
    check's, since this check deletes nothing before its teardown."""
    from botocore.exceptions import ClientError

    own = []
    for connector_id in sorted(ids):
        try:
            connector = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
            raise
        if connector.get("AccessRole") == role_arn:
            own.append(connector_id)
    return own


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-connrole-")
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


def _create_dummy_secret(ctx) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-sftp-secret-")
    resp = sm.create_secret(
        Name=name,
        SecretString=json.dumps({"Password": "not-a-real-password"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = resp["ARN"]
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )
    return secret_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
