"""connector-lifecycle-create-update-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connector-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An SFTP connector's Url/config can be updated post-creation and DescribeConnector
    404s after deletion."""
    transfer = ctx.client("transfer")
    secretsmanager = ctx.client("secretsmanager")

    role_arn = _create_transfer_role(ctx, "connector")

    secret_name = ctx.unique_name("sim2real-transfer-connector-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Username": "partner-user", "Password": "partner-pass"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    initial_url = "sftp://partner.example.com"
    connector_id = transfer.create_connector(
        AccessRole=role_arn,
        Url=initial_url,
        SftpConfig={"UserSecretId": secret_arn, "MaxConcurrentConnections": 1},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ConnectorId"]
    deleted = {"v": False}

    def _cleanup_connector():
        if not deleted["v"]:
            transfer.delete_connector(ConnectorId=connector_id)

    ctx.on_cleanup(_cleanup_connector)

    # A new connector may report PENDING (ConnectorStatus enum) before ACTIVE, so poll off it.
    described = _poll_until(
        lambda: transfer.describe_connector(ConnectorId=connector_id)["Connector"],
        lambda c: c["Status"] != "PENDING",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert described["Url"] == initial_url, f"expected Url={initial_url!r}, got {described['Url']!r}"
    assert described["EgressType"] == "SERVICE_MANAGED", (
        f"expected EgressType=SERVICE_MANAGED for a connector with no VpcConfig, "
        f"got {described['EgressType']!r}"
    )
    assert described["Status"] == "ACTIVE", f"expected Status=ACTIVE, got {described['Status']!r}"

    updated_url = "sftp://partner-updated.example.com"
    transfer.update_connector(ConnectorId=connector_id, Url=updated_url)

    reflected = _poll_until(
        lambda: transfer.describe_connector(ConnectorId=connector_id)["Connector"],
        lambda c: c["Url"] == updated_url,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert reflected["Url"] == updated_url, (
        f"expected DescribeConnector to reflect updated Url={updated_url!r}, "
        f"got {reflected['Url']!r}"
    )

    transfer.delete_connector(ConnectorId=connector_id)
    deleted["v"] = True

    error = _client_error(lambda: transfer.describe_connector(ConnectorId=connector_id))
    assert error == ("ResourceNotFoundException", "Unknown connector"), error

    update_error = _client_error(
        lambda: transfer.update_connector(ConnectorId=connector_id, Url=updated_url)
    )
    assert update_error == ("ResourceNotFoundException", "Unknown connector"), update_error

    listed = transfer.list_connectors()["Connectors"]
    assert all(c["ConnectorId"] != connector_id for c in listed), (
        f"expected {connector_id} absent from ListConnectors after delete, "
        f"but it is still listed"
    )


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_transfer_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-transfer-{suffix}-")
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
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    _wait_for_role(ctx, role_name)
    return role_arn


def _wait_for_role(ctx, role_name, timeout_s=30.0, interval_s=2.0):
    iam = ctx.client("iam")
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
