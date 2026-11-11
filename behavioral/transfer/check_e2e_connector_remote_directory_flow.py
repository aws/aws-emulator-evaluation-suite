"""e2e-connector-remote-directory-flow."""
from __future__ import annotations

import io
import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-connector-remote-directory-flow"
GROUP = "e2e"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SFTP connector to a second Transfer server lists a planted file, moves it (S3 shows the
    same bytes at the new key), deletes it, and a fresh listing no longer shows it."""
    try:
        import paramiko
    except ImportError as exc:

        raise AssertionError(f"paramiko not installed ({exc}); needed to mint the remote server's SSH key pair")

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    role_arn = _create_transfer_role(ctx, bucket)

    remote_server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-remote-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=remote_server_id))
    transfer.start_server(ServerId=remote_server_id)
    _wait_for_server_state(transfer, remote_server_id, "ONLINE", timeout_s=300)

    key = paramiko.RSAKey.generate(2048)
    public_key_body = f"{key.get_name()} {key.get_base64()}"
    remote_username = ctx.unique_name("sim2realremote")
    _retry_on_iam_propagation(
        lambda: transfer.create_user(
            ServerId=remote_server_id,
            UserName=remote_username,
            Role=role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory=f"/{bucket}",
            SshPublicKeyBody=public_key_body,
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=remote_server_id, UserName=remote_username))

    marker = uuid.uuid4().hex
    original_content = f"sim2real-connector-payload-{marker}".encode("utf-8")
    s3.put_object(Bucket=bucket, Key="testdir/testfile.txt", Body=original_content)
    # Keeps "/testdir" a real S3 prefix after the delete: StartDirectoryListing against a
    # vanished prefix never produces an output object.
    s3.put_object(Bucket=bucket, Key="testdir/.keep", Body=b"")

    private_key_buf = io.StringIO()
    key.write_private_key(private_key_buf)
    secret_arn = _create_secret(
        ctx, json.dumps({"Username": remote_username, "PrivateKey": private_key_buf.getvalue()})
    )

    hostname = f"{remote_server_id}.server.transfer.{ctx.region}.amazonaws.com"
    connector_id = _retry_on_iam_propagation(
        lambda: transfer.create_connector(
            Url=f"sftp://{hostname}",
            AccessRole=role_arn,
            SftpConfig={"UserSecretId": secret_arn},
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-connector-")}],
        )
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    _establish_trust_and_verify_connection(transfer, connector_id)

    # 1) Directory listing shows the file we planted directly in the backing bucket.
    listing_text_1 = _run_directory_listing(ctx, transfer, s3, bucket, connector_id, f"/{bucket}/testdir")
    assert "testfile.txt" in listing_text_1, f"planted file missing from initial listing: {listing_text_1!r}"

    # 2) Move it via the connector, and confirm via S3 that the move actually happened remotely.
    transfer.start_remote_move(
        ConnectorId=connector_id,
        SourcePath=f"/{bucket}/testdir/testfile.txt",
        TargetPath=f"/{bucket}/testdir/moved.txt",
    )
    _poll_until_object_state(s3, bucket, "testdir/testfile.txt", should_exist=False, timeout_s=120)
    _poll_until_object_state(s3, bucket, "testdir/moved.txt", should_exist=True, timeout_s=120)
    moved_body = s3.get_object(Bucket=bucket, Key="testdir/moved.txt")["Body"].read()
    assert moved_body == original_content, (
        f"moved object content mismatch: expected {original_content!r}, got {moved_body!r}"
    )

    # 3) Delete it via the connector, and confirm via S3 that it is gone.
    transfer.start_remote_delete(ConnectorId=connector_id, DeletePath=f"/{bucket}/testdir/moved.txt")
    _poll_until_object_state(s3, bucket, "testdir/moved.txt", should_exist=False, timeout_s=120)

    # 4) A fresh directory listing no longer shows either the original or the moved object.
    listing_text_2 = _run_directory_listing(ctx, transfer, s3, bucket, connector_id, f"/{bucket}/testdir")
    assert "testfile.txt" not in listing_text_2 and "moved.txt" not in listing_text_2, (
        f"deleted object still present in post-delete listing: {listing_text_2!r}"
    )


def _establish_trust_and_verify_connection(transfer, connector_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    host_key = None
    result = None
    while time.monotonic() < deadline:
        result = transfer.test_connection(ConnectorId=connector_id)
        host_key = result.get("SftpConnectionDetails", {}).get("HostKey")
        if result.get("Status") == "OK" or host_key:
            break
        time.sleep(2)
    assert host_key, f"TestConnection never reported a host key within {timeout_s}s: {result}"

    if result.get("Status") != "OK":
        transfer.update_connector(ConnectorId=connector_id, SftpConfig={"TrustedHostKeys": [host_key]})
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            result = transfer.test_connection(ConnectorId=connector_id)
            if result.get("Status") in ("OK", "ERROR"):
                break
            time.sleep(2)
    assert result.get("Status") == "OK", f"TestConnection did not succeed after pinning the host key: {result}"


def _run_directory_listing(ctx, transfer, s3, bucket: str, connector_id: str, remote_dir: str) -> str:
    from botocore.exceptions import ClientError

    output_prefix = f"listing-output/{uuid.uuid4().hex}"
    resp = transfer.start_directory_listing(
        ConnectorId=connector_id,
        RemoteDirectoryPath=remote_dir,
        OutputDirectoryPath=f"/{bucket}/{output_prefix}",
    )
    output_key = f"{output_prefix}/{resp['OutputFileName']}"
    timeout_s = 300
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return s3.get_object(Bucket=bucket, Key=output_key)["Body"].read().decode("utf-8")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                raise
            time.sleep(5)
    raise AssertionError(f"directory listing output object {output_key} never appeared within {timeout_s}s")


def _poll_until_object_state(s3, bucket: str, key: str, should_exist: bool, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        exists = _object_exists(s3, bucket, key)
        if exists == should_exist:
            return
        time.sleep(5)
    raise AssertionError(f"s3://{bucket}/{key} never reached exists={should_exist} within {timeout_s}s")


def _object_exists(s3, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except Exception:
        return False


def _wait_for_server_state(transfer, server_id: str, target_state: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state == target_state:
            return
        if state.endswith("_FAILED"):
            raise AssertionError(f"server entered failure state {state}")
        time.sleep(2)
    raise AssertionError(f"server never reached {target_state}, last seen {state}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-transfer-connector-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_secret(ctx, secret_string: str) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("aws/transfer/sim2real-connector-")
    arn = sm.create_secret(Name=name, SecretString=secret_string)["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


def _create_transfer_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-connector-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-and-secrets-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}"},
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
                ],
            }
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="s3-and-secrets-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


def _retry_on_iam_propagation(fn, *, attempts=10, delay_s=8.0):
    """Retry CreateUser/CreateConnector until the new role is assumable by Transfer; IAM exposes
    no condition to poll for that.
    """
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
    raise AssertionError(f"role never became assumable by transfer.amazonaws.com: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
