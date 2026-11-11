"""update-connector-nonexistent-resource-not-found-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connector-nonexistent-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConnector on a well-formed but nonexistent ConnectorId is ResourceNotFoundException,
    while an update on a real connector succeeds and is untouched by the rejected call."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx)
    secret_arn = _create_sftp_secret(ctx)
    connector_id = _retry_role_propagation(
        lambda: transfer.create_connector(
            Url="sftp://sim2real-original.example.com",
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

    # Positive control: a well-formed single-field update succeeds.
    updated_url = "sftp://sim2real-updated.example.com"
    transfer.update_connector(ConnectorId=connector_id, Url=updated_url)
    desc = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
    assert desc["Url"] == updated_url, f"expected Url {updated_url!r} after update, got {desc.get('Url')!r}"

    # Negative: a well-formed ConnectorId (matches ^c-([0-9a-f]{17})$) that was never created.
    bogus_connector_id = "c-" + "0" * 17
    code, message = _error(
        lambda: transfer.update_connector(ConnectorId=bogus_connector_id, Url="sftp://sim2real-bogus.example.com")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unknown connector", f"expected message 'Unknown connector', got {message!r}"

    # The rejected call left the real connector's Url unchanged.
    desc2 = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
    assert desc2["Url"] == updated_url, (
        f"rejected UpdateConnector on {bogus_connector_id!r} mutated the real connector: "
        f"expected Url to remain {updated_url!r}, got {desc2.get('Url')!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    """The Secrets Manager secret SftpConfig.UserSecretId requires; CreateConnector does not
    inspect its content."""
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
