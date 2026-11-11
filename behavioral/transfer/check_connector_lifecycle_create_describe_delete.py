"""connector-lifecycle-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connector-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnector reaches ACTIVE and is describable via DescribeConnector; DeleteConnector
    removes it, so a subsequent Describe AND a subsequent Delete on the same id both 404."""
    tf = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    secret_arn = _create_sftp_secret(ctx)
    url = "sftp://sim2real-connector-test.example.com"

    resp = _retry_role_propagation(
        lambda: tf.create_connector(
            Url=url,
            AccessRole=role_arn,
            SftpConfig={"UserSecretId": secret_arn},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    connector_id = resp["ConnectorId"]
    ctx.on_cleanup(lambda: _safe_delete_connector(tf, connector_id))

    status = _poll_until(
        lambda: tf.describe_connector(ConnectorId=connector_id)["Connector"]["Status"],
        lambda s: s != "PENDING",
        timeout_s=60,
        interval_s=5,
        description="connector leaving PENDING",
    )
    assert status == "ACTIVE", f"expected a well-formed SFTP connector to provision ACTIVE, got {status!r}"

    described = tf.describe_connector(ConnectorId=connector_id)["Connector"]
    assert described["ConnectorId"] == connector_id, (
        f"expected DescribeConnector to echo {connector_id!r}, got {described['ConnectorId']!r}"
    )
    assert described["Url"] == url, f"expected Url {url!r}, got {described['Url']!r}"
    assert described["AccessRole"] == role_arn, (
        f"expected AccessRole {role_arn!r}, got {described['AccessRole']!r}"
    )

    tf.delete_connector(ConnectorId=connector_id)

    error = _client_error(lambda: tf.describe_connector(ConnectorId=connector_id))
    assert error == ("ResourceNotFoundException", "Unknown connector"), error

    delete_error = _client_error(lambda: tf.delete_connector(ConnectorId=connector_id))
    assert delete_error == ("ResourceNotFoundException", "Unknown connector"), delete_error


def _create_sftp_secret(ctx) -> str:
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-connector-secret-")
    secret_value = json.dumps({"Username": "sim2real-test-user", "Password": "sim2real-test-pass"})
    resp = sm.create_secret(
        Name=secret_name, SecretString=secret_value,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = resp["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_secret(sm, secret_name))
    return secret_arn


def _safe_delete_secret(sm, secret_name: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_transfer_role(ctx) -> str:

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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_connector(tf, connector_id: str) -> None:
    try:
        tf.delete_connector(ConnectorId=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail with a specific error, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
