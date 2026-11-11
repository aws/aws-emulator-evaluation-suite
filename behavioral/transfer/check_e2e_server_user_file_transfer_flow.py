"""e2e-server-user-file-transfer-flow."""
from __future__ import annotations

import json
import time

CHECK = "e2e-server-user-file-transfer-flow"
GROUP = "e2e"
SERVICES = ["transfer"]

from behavioral_harness import tags

from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding as _Encoding,
    NoEncryption as _NoEncryption,
    PrivateFormat as _PrivateFormat,
    PublicFormat as _PublicFormat,
)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartFileTransfer through an SFTP connector wired to a Transfer server + user completes
    end to end over the SFTP protocol: ListFileTransferResults reports COMPLETED and the file
    lands byte-identically in S3."""

    transfer = ctx.client("transfer")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    secretsmanager = ctx.client("secretsmanager")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket = ctx.unique_name("sim2real-transfer-e2e-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket, region)

    user_role_arn = _create_role(
        ctx,
        iam,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource": f"arn:aws:s3:::{bucket}"},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                 "Resource": f"arn:aws:s3:::{bucket}/*"},
            ],
        },
    )
    connector_role_arn = _create_role(
        ctx,
        iam,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource": f"arn:aws:s3:::{bucket}"},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                 "Resource": f"arn:aws:s3:::{bucket}/*"},
                {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
                 "Resource": f"arn:aws:secretsmanager:{region}:{account_id}:secret:aws/transfer/*"},
            ],
        },
    )

    host_private_pem, _ = _generate_rsa_keypair()
    server_tag_name = ctx.unique_name("sim2real-transfer-e2e-srv-")
    server_id = transfer.create_server(
        Protocols=["SFTP"],
        HostKey=host_private_pem,
        Tags=[{"Key": "Name", "Value": server_tag_name}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.start_server(ServerId=server_id)
    _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda s: s == "ONLINE",
        timeout_s=300.0,
        interval_s=10.0,
    )

    user_private_pem, user_public_openssh = _generate_rsa_keypair()
    user_name = ctx.unique_name("sim2realuser").replace("-", "")[:32]
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=user_role_arn,
        HomeDirectoryType="PATH",
        HomeDirectory=f"/{bucket}",
        SshPublicKeyBody=user_public_openssh,
        Tags=[{"Key": "Name", "Value": user_name}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    secret_name = ctx.unique_name("aws/transfer/sim2real-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"Username": user_name, "PrivateKey": user_private_pem}),
        Tags=[{"Key": "Name", "Value": secret_name}],
    )["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    server_host = f"{server_id}.server.transfer.{region}.amazonaws.com"
    connector_id = transfer.create_connector(
        Url=f"sftp://{server_host}",
        AccessRole=connector_role_arn,
        SftpConfig={"UserSecretId": secret_arn},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-e2e-conn-")}],
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    # The server's host key isn't known to the connector yet, and TestConnection does not
    # reliably surface it on the very first call (observed on real AWS: the initial response
    # can lack "HostKey" entirely) -- poll until it appears, then pin it via UpdateConnector.
    host_key = _poll_until(
        lambda: transfer.test_connection(ConnectorId=connector_id)
        .get("SftpConnectionDetails", {})
        .get("HostKey"),
        lambda k: bool(k),
        timeout_s=300.0,
        interval_s=10.0,
    )
    transfer.update_connector(
        ConnectorId=connector_id,
        SftpConfig={"UserSecretId": secret_arn, "TrustedHostKeys": [host_key]},
    )

    # IAM role trust/permissions can take a few seconds to propagate; retry the
    # connectivity probe against that observable condition rather than sleeping blind.
    test_result = _poll_until(
        lambda: transfer.test_connection(ConnectorId=connector_id),
        lambda r: r["Status"] == "OK",
        timeout_s=120.0,
        interval_s=10.0,
    )
    assert test_result["Status"] == "OK", f"connector could not reach the server: {test_result.get('StatusMessage')}"

    source_key = "outbound/sim2real-e2e-test.txt"
    payload = b"sim2real transfer e2e payload"
    s3.put_object(Bucket=bucket, Key=source_key, Body=payload)

    # A freshly-online SFTP loopback connector can drop its first session even after
    # TestConnection reports OK (observed on real AWS: StartFileTransfer's own transfer
    # attempt fails with FailureCode CONNECTION_ERROR / "Connection closed" once, then
    # succeeds moments later). Retry the transfer itself -- bounded, and still demanding
    # an eventual COMPLETED -- rather than accepting the transient failure as terminal.
    result = None
    # Three 180 s transfer polls plus pauses, capped by the check's remaining time.
    retry_deadline = time.monotonic() + min(600.0, ctx.time_left() or 600.0)
    while True:
        transfer_id = transfer.start_file_transfer(
            ConnectorId=connector_id,
            SendFilePaths=[f"/{bucket}/{source_key}"],
            RemoteDirectoryPath=f"/{bucket}",
        )["TransferId"]

        results = _poll_until(
            lambda: transfer.list_file_transfer_results(ConnectorId=connector_id, TransferId=transfer_id)[
                "FileTransferResults"
            ],
            lambda rs: bool(rs) and rs[0]["StatusCode"] in ("COMPLETED", "FAILED"),
            timeout_s=180.0,
            interval_s=2.0,
        )
        assert len(results) == 1, f"expected exactly one file transfer result, got {len(results)}: {results}"
        result = results[0]
        if result["StatusCode"] == "COMPLETED" or result.get("FailureCode") != "CONNECTION_ERROR":
            break
        if time.monotonic() >= retry_deadline:
            break
        time.sleep(2.0)
    assert result["StatusCode"] == "COMPLETED", f"file transfer did not complete after retries: {result}"
    assert result["FilePath"] == f"/{bucket}/{source_key}", (
        f"expected FilePath /{bucket}/{source_key}, got {result['FilePath']!r}"
    )

    landed = s3.get_object(Bucket=bucket, Key="sim2real-e2e-test.txt")["Body"].read()
    assert landed == payload, (
        f"the transferred file did not land byte-identically: expected {payload!r}, got {landed!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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


def _create_bucket(ctx, s3, bucket, region) -> None:
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's default region and rejects an explicit LocationConstraint
    # for it; this is a create_bucket API quirk, not a resource pinned to that region.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_role(ctx, iam, inline_policy):
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    policy_name = "inline"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
