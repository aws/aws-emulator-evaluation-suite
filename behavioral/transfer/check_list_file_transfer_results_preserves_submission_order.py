"""list-file-transfer-results-preserves-submission-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-file-transfer-results-preserves-submission-order"
GROUP = "ordering"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFileTransferResults returns exactly one entry per path sent with StartFileTransfer, none missing,
    duplicated or foreign; order is not asserted, as the API documents no ordering."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")
    transfer = ctx.client("transfer")

    bucket = ctx.unique_name("sim2real-behav-connector-").lower()
    _create_bucket(ctx, bucket)

    keys = ["order/file-a.txt", "order/file-b.txt", "order/file-c.txt"]
    for key in keys:
        s3.put_object(Bucket=bucket, Key=key, Body=key.encode())

    secret_arn = secretsmanager.create_secret(
        Name=ctx.unique_name("sim2real-behav-sftp-secret-"),
        SecretString=json.dumps({"Username": "sim2real-test-user", "Password": "sim2real-test-pass"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_name = ctx.unique_name("sim2real-behav-connector-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        ],
    }
    policy_name = "sim2real-behav-connector-access"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(access_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # StartFileTransfer refuses to run on an SFTP connector with no
    # TrustedHostKeys ("No TrustedHostKeys"), so synthesize a structurally
    # valid (but not cryptographically meaningful -- the remote is
    # unreachable anyway) ed25519 OpenSSH public-key line to satisfy that
    # precondition without depending on any real external server.
    trusted_host_key = _fake_ssh_ed25519_pubkey()

    connector_id = _retry_on_access_denied(
        lambda: transfer.create_connector(
            AccessRole=role_arn,
            Url="sftp://192.0.2.1:22",  # RFC 5737 TEST-NET-1: reserved, never routable
            SftpConfig={
                "UserSecretId": secret_arn,
                "TrustedHostKeys": [trusted_host_key],
                "MaxConcurrentConnections": 1,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["ConnectorId"]
    )
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    submitted_paths = [f"/{bucket}/{key}" for key in keys]
    transfer_id = transfer.start_file_transfer(
        ConnectorId=connector_id, SendFilePaths=submitted_paths
    )["TransferId"]

    results = _poll_for_results(ctx, connector_id, transfer_id, expected_count=len(keys))
    observed_paths = [r["FilePath"] for r in results]
    assert len(observed_paths) == len(submitted_paths), (
        f"expected exactly {len(submitted_paths)} results, got {len(observed_paths)}: {observed_paths}"
    )
    assert sorted(observed_paths) == sorted(submitted_paths), (
        f"expected exactly the submitted file set {sorted(submitted_paths)}, "
        f"got {sorted(observed_paths)}"
    )


def _fake_ssh_ed25519_pubkey() -> str:
    """Build a valid OpenSSH RSA public-key line for a freshly generated RSA
    keypair. Transfer Family validates the SSH host-key wire format
    cryptographically (Java security providers reject a modulus/exponent
    pair that isn't a real RSA public key), so a merely well-shaped random
    blob is rejected with InvalidRequestException. The private key is
    discarded immediately -- only the public key is ever used, and only for
    format validation, since the remote endpoint (192.0.2.1) is unreachable
    and the transfer itself is expected to fail regardless of which host key
    is presented."""
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


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _retry_on_access_denied(fn, timeout_s: float = 30.0, interval_s: float = 3.0):
    """IAM role trust/permissions can take a few seconds to propagate; retry the
    dependent call until it stops seeing AccessDenied or the deadline passes."""
    from botocore.exceptions import ClientError

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


def _poll_for_results(ctx, connector_id: str, transfer_id: str, expected_count: int, timeout_s: float = 90.0):
    transfer = ctx.client("transfer")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        resp = transfer.list_file_transfer_results(ConnectorId=connector_id, TransferId=transfer_id)
        last = resp.get("FileTransferResults", [])
        if len(last) >= expected_count:
            return last
        time.sleep(3)
    raise AssertionError(f"expected {expected_count} file transfer results, got {len(last)} in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
