"""connector-create-describe-delete-404."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connector-create-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnector is describable and reaches ACTIVE; DeleteConnector causes Describe to 404."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)
    secret_arn = _create_sftp_secret(ctx)
    url = "sftp://sim2real-test.example.com"

    connector_id = _retry_role_propagation(
        lambda: transfer.create_connector(
            Url=url,
            AccessRole=role_arn,
            SftpConfig={"TrustedHostKeys": [], "UserSecretId": secret_arn},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["ConnectorId"]

    def _cleanup_connector():
        try:
            transfer.delete_connector(ConnectorId=connector_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_connector)

    status = _poll_until(
        lambda: transfer.describe_connector(ConnectorId=connector_id)["Connector"]["Status"],
        lambda s: s != "PENDING",
        timeout_s=60,
        interval_s=5,
    )
    assert status == "ACTIVE", f"expected a well-formed SFTP connector to provision ACTIVE, got {status}"

    desc = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
    assert desc["Url"] == url, f"expected describe_connector to reflect the created Url {url!r}, got {desc['Url']!r}"

    transfer.delete_connector(ConnectorId=connector_id)
    error = _client_error(lambda: transfer.describe_connector(ConnectorId=connector_id))
    assert error == ("ResourceNotFoundException", "Unknown connector"), error

    update_error = _client_error(lambda: transfer.update_connector(ConnectorId=connector_id, Url=url))
    assert update_error == ("ResourceNotFoundException", "Unknown connector"), update_error


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last result: {last!r}")


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_sftp_secret(ctx):
    """SftpConfig.UserSecretId is required when creating an SFTP connector; it must be the
    ARN of a Secrets Manager secret holding the SFTP user's password/private key. Its
    content is never inspected at CreateConnector time, only its existence/ARN format."""
    secretsmanager = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-transfer-sftp-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Password": "sim2real-placeholder-password"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]

    def _cleanup():
        try:
            secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return secret_arn



def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidRequestException", "AccessDenied", "AccessDeniedException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
