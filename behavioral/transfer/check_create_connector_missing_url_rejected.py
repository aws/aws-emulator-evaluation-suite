"""create-connector-missing-url-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connector-missing-url-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnector without a Url and without either As2Config or SftpConfig has no
    way to know what kind of connector to build, and is rejected with
    InvalidRequestException rather than silently defaulting to some connector type."""
    transfer = ctx.client("transfer")
    secretsmanager = ctx.client("secretsmanager")
    role_arn = _create_transfer_role(ctx)

    ids_before_reject = _connector_ids(transfer)
    error = _client_error(lambda: transfer.create_connector(AccessRole=role_arn))
    assert error == ("InvalidRequestException", "One of As2Config or SftpConfig must be specified"), error

    # Effect absent: the rejected call must not have created a connector as a side effect.
    ids_after_reject = _connector_ids(transfer)
    created = _own_connectors(transfer, ids_after_reject - ids_before_reject, role_arn)
    assert created == [], f"rejected create_connector must create nothing, got new connector(s) {created}"

    # Positive control: supplying a Url plus a valid SftpConfig (a real Secrets Manager
    # secret holding the SFTP user's credentials, as CreateConnector requires) is
    # accepted.
    secret_name = ctx.unique_name("sim2real-transfer-connector-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Username": "sim2real-user", "Password": "sim2real-Passw0rd!"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    connector_id = _retry_role_propagation(
        lambda: transfer.create_connector(
            AccessRole=role_arn,
            Url="sftp://sim2real-behavioral-test.example.com",
            SftpConfig={"UserSecretId": secret_arn},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))
    assert connector_id not in ids_after_reject, (
        f"positive-control connector id {connector_id} unexpectedly already existed"
    )
    created = _own_connectors(transfer, _connector_ids(transfer) - ids_before_reject, role_arn)
    assert created == [connector_id], (
        f"expected exactly the positive-control connector {connector_id} on this AccessRole, got {created}"
    )
    described = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
    assert described["Url"] == "sftp://sim2real-behavioral-test.example.com"


def _connector_ids(transfer) -> set[str]:
    ids: set[str] = set()
    for page in transfer.get_paginator("list_connectors").paginate():
        ids.update(connector["ConnectorId"] for connector in page.get("Connectors", []))
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


def _create_transfer_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
