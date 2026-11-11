"""file-transfer-result-status-visibility-ttl."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "file-transfer-result-status-visibility-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["transfer"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_PAYLOAD = b"sim2real behavioral fixture content"

from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding as _Encoding,
    NoEncryption as _NoEncryption,
    PrivateFormat as _PrivateFormat,
    PublicFormat as _PublicFormat,
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Right after StartFileTransfer, ListFileTransferResults lists the sent path as QUEUED,
    IN_PROGRESS or COMPLETED; it then reaches COMPLETED and the source bytes land remotely."""

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    bucket = ctx.unique_name("sim2real-behav-ftr-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})

    key = "source.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD)

    user_role_arn = _create_transfer_role(
        ctx,
        iam,
        "sim2real-behav-ftr-userrole-",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
        ],
    )
    connector_role_arn = _create_transfer_role(
        ctx,
        iam,
        "sim2real-behav-ftr-connrole-",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "arn:aws:secretsmanager:*:*:secret:aws/transfer/*",
            },
        ],
    )

    host_private_pem, _ = _generate_rsa_keypair()
    server_id = transfer.create_server(
        Protocols=["SFTP"], HostKey=host_private_pem, Tags=_TAGS
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.start_server(ServerId=server_id)
    ctx.on_cleanup(lambda: _best_effort_stop(transfer, server_id))
    _poll_until(
        probe=lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        predicate=lambda s: s == "ONLINE",
        timeout_s=400,
        interval_s=5,
    )

    user_private_pem, user_public_openssh = _generate_rsa_keypair()
    user_name = ctx.unique_name("sim2realuser").replace("-", "")[:32]
    _retry_on_iam_propagation(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=user_name,
            Role=user_role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory=f"/{bucket}",
            SshPublicKeyBody=user_public_openssh,
            Tags=_TAGS,
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    secret_name = ctx.unique_name("aws/transfer/sim2real-behav-ftr-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Username": user_name, "PrivateKey": user_private_pem}),
        Tags=_TAGS,
    )["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    server_host = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    connector_id = _retry_on_iam_propagation(
        lambda: transfer.create_connector(
            Url=f"sftp://{server_host}",
            AccessRole=connector_role_arn,
            SftpConfig={"UserSecretId": secret_arn},
            Tags=_TAGS,
        )
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    # The server's host key isn't known to the connector yet; TestConnection surfaces the
    # observed host key so it can be pinned via UpdateConnector before transferring.
    probe = _poll_until(
        probe=lambda: transfer.test_connection(ConnectorId=connector_id),
        predicate=lambda r: "SftpConnectionDetails" in r and r["SftpConnectionDetails"].get("HostKey"),
        timeout_s=180,
        interval_s=10,
    )
    host_key = probe["SftpConnectionDetails"]["HostKey"]
    transfer.update_connector(
        ConnectorId=connector_id,
        SftpConfig={"UserSecretId": secret_arn, "TrustedHostKeys": [host_key]},
    )

    test_result = _poll_until(
        probe=lambda: transfer.test_connection(ConnectorId=connector_id),
        predicate=lambda r: r["Status"] == "OK",
        timeout_s=120,
        interval_s=10,
    )
    assert test_result["Status"] == "OK", f"connector could not reach the server: {test_result.get('StatusMessage')}"

    # RemoteDirectoryPath differs from the source key; otherwise the landed-bytes check is
    # vacuous because the user's home directory is the bucket root.
    landed_key = "landed/source.txt"
    transfer_id = transfer.start_file_transfer(
        ConnectorId=connector_id,
        SendFilePaths=[f"/{bucket}/{key}"],
        RemoteDirectoryPath=f"/{bucket}/landed",
    )["TransferId"]

    first_results = transfer.list_file_transfer_results(
        ConnectorId=connector_id, TransferId=transfer_id
    )["FileTransferResults"]
    assert [r["FilePath"] for r in first_results] == [f"/{bucket}/{key}"], first_results
    first_status = first_results[0]["StatusCode"]
    # A small file can finish before the first read; no QUEUED/IN_PROGRESS duration is documented.
    assert first_status in ("QUEUED", "IN_PROGRESS", "COMPLETED"), (
        f"expected QUEUED, IN_PROGRESS or COMPLETED immediately after StartFileTransfer, got "
        f"{first_status!r}"
    )

    final_result = _poll_until(
        probe=lambda: transfer.list_file_transfer_results(
            ConnectorId=connector_id, TransferId=transfer_id
        )["FileTransferResults"][0],
        predicate=lambda r: r["StatusCode"] in ("COMPLETED", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert final_result["StatusCode"] == "COMPLETED", (
        f"expected COMPLETED, got {final_result['StatusCode']!r}: {final_result!r}"
    )
    assert "FailureCode" not in final_result and "FailureMessage" not in final_result, final_result

    landed_body = s3.get_object(Bucket=bucket, Key=landed_key)["Body"].read()
    assert landed_body == _PAYLOAD, (
        f"the file at the routed destination {landed_key!r} does not match the source bytes: "
        f"{landed_body!r} vs {_PAYLOAD!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _best_effort_stop(transfer, server_id: str) -> None:
    try:
        transfer.stop_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    objects = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _generate_rsa_keypair():
    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=_Encoding.PEM,
        format=_PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_NoEncryption(),
    ).decode()
    public_openssh = private_key.public_key().public_bytes(
        encoding=_Encoding.OpenSSH, format=_PublicFormat.OpenSSH
    ).decode()
    return private_pem, public_openssh


def _create_transfer_role(ctx, iam, name_prefix: str, statements) -> str:
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="access", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="access"))
    return role_arn


def _retry_on_iam_propagation(fn, *, attempts: int = 10, delay_s: float = 8.0):
    """Retry fn until IAM propagates the new role to Transfer; IAM exposes no condition to poll
    for that."""
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidRequestException"):
                last = exc
                time.sleep(delay_s)
                continue
            raise
    raise AssertionError(f"role never propagated through IAM in time: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

