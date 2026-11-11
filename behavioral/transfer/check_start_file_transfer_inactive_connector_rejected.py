"""start-file-transfer-inactive-connector-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-file-transfer-inactive-connector-rejected"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartFileTransfer and DescribeConnector on a well-formed but nonexistent ConnectorId fail with
    ResourceNotFoundException and the message "Unknown connector", while StartFileTransfer on a real
    SFTP connector is accepted and registers exactly one transfer result for the sent file path."""
    transfer = ctx.client("transfer")
    fake_connector_id = "c-00000000000000000"

    code, message = _err(
        lambda: transfer.start_file_transfer(
            ConnectorId=fake_connector_id,
            RetrieveFilePaths=["/inbox/file.txt"],
            LocalDirectoryPath="/inbox",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Unknown connector", f"unexpected StartFileTransfer message {message!r}"

    # The id never resolved to a connector, before or after the call.
    describe_code, describe_message = _err(
        lambda: transfer.describe_connector(ConnectorId=fake_connector_id)
    )
    assert describe_code == "ResourceNotFoundException", describe_code
    assert describe_message == "Unknown connector", (
        f"unexpected DescribeConnector message {describe_message!r}"
    )

    # Positive control. StartFileTransfer validates synchronously and transfers asynchronously,
    # so the unroutable endpoint (192.0.2.1, RFC 5737 TEST-NET-1) does not matter. SFTP, not
    # AS2, because ListFileTransferResults is not supported for AS2 connectors.
    role_arn = _create_transfer_role(ctx)
    bucket_name = _create_bucket_with_object(ctx)
    secret_arn = _create_user_secret(ctx)
    trusted_host_key = _fake_ssh_rsa_pubkey()
    connector_id = _retry_on_iam_propagation(
        lambda: transfer.create_connector(
            Url="sftp://192.0.2.1:22",
            AccessRole=role_arn,
            SftpConfig={"UserSecretId": secret_arn, "TrustedHostKeys": [trusted_host_key]},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["ConnectorId"]
    )
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    file_path = f"/{bucket_name}/test.txt"
    started = transfer.start_file_transfer(
        ConnectorId=connector_id,
        SendFilePaths=[file_path],
    )
    transfer_id = started.get("TransferId")
    assert isinstance(transfer_id, str) and transfer_id

    # Independent read: the transfer was registered against the connector, not just echoed.
    results = transfer.list_file_transfer_results(
        ConnectorId=connector_id, TransferId=transfer_id
    )["FileTransferResults"]
    assert len(results) == 1, f"expected exactly one file transfer result, got {results!r}"
    result = results[0]
    assert result["FilePath"] == file_path, (
        f"expected registered file path {file_path!r}, got {result['FilePath']!r}"
    )
    assert result["StatusCode"] in ("QUEUED", "IN_PROGRESS", "COMPLETED", "FAILED"), (
        f"unexpected StatusCode {result['StatusCode']!r}"
    )


def _err(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfrole-")
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


def _create_user_secret(ctx) -> str:
    secretsmanager = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("aws/transfer/sim2real-behav-sf-")
    resp = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps(
            {"Username": "sim2real-test-user", "Password": "sim2real-test-pass"}
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = resp["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )
    return secret_arn


def _fake_ssh_rsa_pubkey() -> str:
    """A structurally valid OpenSSH RSA public-key line for SftpConfig.TrustedHostKeys;
    Transfer Family validates the key format, and the private key is discarded."""
    import base64
    import struct

    from cryptography.hazmat.primitives.asymmetric import rsa

    def _mpint(value: int) -> bytes:
        b = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return struct.pack(">I", len(b)) + b

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    key_type = b"ssh-rsa"
    blob = struct.pack(">I", len(key_type)) + key_type + _mpint(numbers.e) + _mpint(numbers.n)
    return "ssh-rsa " + base64.b64encode(blob).decode()


def _retry_on_iam_propagation(fn, timeout_s: float = 30.0, interval_s: float = 3.0):
    """IAM role trust can take a few seconds to propagate; retry the dependent call until
    it stops seeing AccessDenied/invalid-role or the deadline passes."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] not in (
                "AccessDeniedException",
                "InvalidRequestException",
                "InvalidParameterValueException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_bucket_with_object(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-sfbkt-").lower()
    region = s3.meta.region_name
    if region and region != "us-east-1":
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    else:
        s3.create_bucket(Bucket=bucket_name)

    def _cleanup() -> None:
        s3.delete_object(Bucket=bucket_name, Key="test.txt")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_object(Bucket=bucket_name, Key="test.txt", Body=b"hello")
    return bucket_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
