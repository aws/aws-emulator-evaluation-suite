"""test-connection-connector-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "test-connection-connector-not-found"
GROUP = 'error-semantics'
SERVICES = ['transfer']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestConnection on an ACTIVE connector does not fail with ResourceNotFoundException, while a never-issued
    ConnectorId and the id of a deleted connector both fail with ResourceNotFoundException "Unknown connector"."""
    tf = ctx.client('transfer')

    role_arn = _create_transfer_role(ctx)
    secret_arn = _create_sftp_secret(ctx)
    connector_id = _retry_role_propagation(
        lambda: tf.create_connector(
            Url="sftp://sim2real-test.example.com",
            AccessRole=role_arn,
            SftpConfig={"TrustedHostKeys": [], "UserSecretId": secret_arn},
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-connector-")}],
        )
    )["ConnectorId"]

    def _cleanup_connector():
        try:
            tf.delete_connector(ConnectorId=connector_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_connector)

    status = _poll_until(
        lambda: tf.describe_connector(ConnectorId=connector_id)["Connector"]["Status"],
        lambda s: s != "PENDING",
        timeout_s=60,
        interval_s=5,
    )
    assert status == "ACTIVE", f"expected connector to provision ACTIVE before use, got {status}"

    try:
        tf.test_connection(ConnectorId=connector_id)
        positive_code = None
    except ClientError as exc:
        positive_code = exc.response.get('Error', {}).get('Code')
    assert positive_code != 'ResourceNotFoundException', (
        f"TestConnection against a live connector must not itself 404; got {positive_code}"
    )

    never_issued_code, never_issued_msg = _err(
        lambda: tf.test_connection(ConnectorId='c-0000000000000000f'))
    assert never_issued_code == 'ResourceNotFoundException', never_issued_code
    assert never_issued_msg == 'Unknown connector', (
        f"unexpected never-issued connector message {never_issued_msg!r}")

    tf.delete_connector(ConnectorId=connector_id)
    deleted_code, deleted_msg = _err(lambda: tf.test_connection(ConnectorId=connector_id))
    assert deleted_code == 'ResourceNotFoundException', (
        f"expected ResourceNotFoundException for a just-deleted connector id, got {deleted_code}"
    )
    assert deleted_msg == 'Unknown connector', (
        f"unexpected just-deleted connector message {deleted_msg!r}"
    )


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_transfer_role(ctx):
    iam = ctx.client('iam')
    role_name = ctx.unique_name('sim2real-transfer-role-')
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
        Tags=[{"Key": "Name", "Value": role_name}],
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
    secretsmanager = ctx.client('secretsmanager')
    secret_name = ctx.unique_name('sim2real-transfer-sftp-secret-')
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Password": "sim2real-placeholder-password"}),
        Tags=[{"Key": "Name", "Value": secret_name}],
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


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
