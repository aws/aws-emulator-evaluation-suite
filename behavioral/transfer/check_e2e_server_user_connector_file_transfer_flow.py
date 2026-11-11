"""e2e-server-user-connector-file-transfer-flow."""
from __future__ import annotations

import json
import time
from typing import Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-server-user-connector-file-transfer-flow"
GROUP = "e2e"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Through an SFTP connector that loops back to its own Transfer server, StartFileTransfer yields exactly one
    COMPLETED result with FilePath /<bucket>/<key> in ListFileTransferResults, and the file lands in S3 with the source
    bytes."""
    public_key_str, private_key_pem = _generate_ssh_keypair()

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    source_key = "outgoing/sim2real-source.txt"
    source_bytes = b"sim2real end-to-end transfer payload \x00\x01\x02"
    s3.put_object(Bucket=bucket, Key=source_key, Body=source_bytes)

    user_name = ctx.unique_name("sim2real-e2e-user-").replace("_", "-")
    secret_name = f"aws/transfer/{ctx.unique_name('sim2real-e2e-secret-')}"

    secret_arn = _create_secret(
        ctx, secret_name, json.dumps({"Username": user_name, "PrivateKey": private_key_pem})
    )

    user_role_arn = _create_role(
        ctx,
        "transfer.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ListHomeBucket",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
                {
                    "Sid": "HomeDirObjectAccess",
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:GetObjectVersion"],
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                },
            ],
        },
    )
    connector_role_arn = _create_role(
        ctx,
        "transfer.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadSourceBucket",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
                {
                    "Sid": "ReadSourceObject",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                },
                {
                    "Sid": "GetConnectorSecret",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": secret_arn,
                },
            ],
        },
    )
    server_id = transfer.create_server(
        EndpointType="PUBLIC",
        IdentityProviderType="SERVICE_MANAGED",
        Protocols=["SFTP"],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["ServerId"]

    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.start_server(ServerId=server_id)
    _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda state: state == "ONLINE",
        timeout_s=300.0,
        interval_s=10.0,
    )

    _retry_on_access_denied(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=user_name,
            Role=user_role_arn,
            HomeDirectory=f"/{bucket}/incoming",
            HomeDirectoryType="PATH",
            SshPublicKeyBody=public_key_str,
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    url = f"sftp://{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    connector_id = _retry_on_access_denied(
        lambda: transfer.create_connector(
            Url=url,
            AccessRole=connector_role_arn,
            SftpConfig={"UserSecretId": secret_arn},
        )
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    _poll_until(
        lambda: transfer.describe_connector(ConnectorId=connector_id)["Connector"]["Status"],
        lambda status: status in ("ACTIVE", "ERRORED"),
        timeout_s=120.0,
        interval_s=5.0,
    )

    # discover the server's host key via TestConnection (trust-on-first-use, per
    # AWS Transfer Family's documented SFTP connector workflow), then pin it
    host_key = _poll_until(
        lambda: transfer.test_connection(ConnectorId=connector_id)
        .get("SftpConnectionDetails", {})
        .get("HostKey"),
        lambda key: bool(key),
        timeout_s=120.0,
        interval_s=10.0,
    )
    transfer.update_connector(
        ConnectorId=connector_id,
        SftpConfig={"UserSecretId": secret_arn, "TrustedHostKeys": [host_key]},
    )

    _poll_until(
        lambda: transfer.test_connection(ConnectorId=connector_id)["Status"],
        lambda status: status == "OK",
        timeout_s=120.0,
        interval_s=10.0,
    )

    transfer_id = transfer.start_file_transfer(
        ConnectorId=connector_id,
        SendFilePaths=[f"/{bucket}/{source_key}"],
        RemoteDirectoryPath=f"/{bucket}/incoming",
    )["TransferId"]

    results = _poll_until(
        lambda: transfer.list_file_transfer_results(ConnectorId=connector_id, TransferId=transfer_id)[
            "FileTransferResults"
        ],
        lambda results: bool(results) and results[0]["StatusCode"] in ("COMPLETED", "FAILED"),
        timeout_s=180.0,
        interval_s=10.0,
    )

    assert len(results) == 1, f"expected exactly one file transfer result, got {len(results)}"
    result = results[0]
    assert result["StatusCode"] == "COMPLETED", (
        f"file transfer did not complete: {result.get('FailureCode')} {result.get('FailureMessage')}"
    )
    assert result["FilePath"] == f"/{bucket}/{source_key}", f"unexpected FilePath {result['FilePath']!r}"

    # observe the downstream effect directly: the bytes actually landed in S3
    landed = s3.get_object(Bucket=bucket, Key=f"incoming/{source_key.split('/')[-1]}")["Body"].read()
    assert landed == source_bytes, "the file that landed at the destination does not match the source bytes"


def _poll_until(probe: Callable[[], object], predicate: Callable[[object], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _retry_on_access_denied(fn: Callable[[], object], attempts: int = 8, delay_s: float = 8.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "InvalidRequestException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _generate_ssh_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return public_bytes.decode("utf-8"), private_pem.decode("utf-8")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-transfer-e2e-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_secret(ctx, name: str, secret_string: str) -> str:
    sm = ctx.client("secretsmanager")
    resp = sm.create_secret(Name=name, SecretString=secret_string)
    secret_arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    return secret_arn


def _create_role(ctx, trust_service: str, inline_policy: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-e2e-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(inline_policy))

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
