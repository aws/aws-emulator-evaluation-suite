"""e2e-server-user-transfer-flow."""
from __future__ import annotations

import io
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-server-user-transfer-flow"
GROUP = "e2e"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:native", "plane:data")
def run(ctx) -> None:
    """End-to-end: create a server and grant a user access, then perform a REAL SFTP round
    trip (native protocol, not just the control-plane) -- upload a file as that user and
    observe it land, byte-for-byte, in the backing S3 bucket -- before tearing everything down."""
    try:
        import paramiko
    except ImportError as exc:

        raise AssertionError(f"paramiko not installed ({exc}); needed for a native SFTP round trip")

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    role_arn = _create_transfer_role(ctx, bucket)

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-e2e-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.start_server(ServerId=server_id)
    _wait_for_server_state(transfer, server_id, "ONLINE", timeout_s=300)

    key = paramiko.RSAKey.generate(2048)
    public_key_body = f"{key.get_name()} {key.get_base64()}"
    username = ctx.unique_name("sim2reale2e")
    _retry_role_propagation(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=username,
            Role=role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory=f"/{bucket}",
            SshPublicKeyBody=public_key_body,
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))

    hostname = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    content = f"sim2real-e2e-payload-{uuid.uuid4().hex}".encode("utf-8")
    object_key = "sim2real-uploaded.txt"

    transport = _connect_sftp(hostname, username, key, timeout_s=180)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.putfo(io.BytesIO(content), object_key)
        sftp.close()
    finally:
        transport.close()

    body = s3.get_object(Bucket=bucket, Key=object_key)["Body"].read()
    assert body == content, "file uploaded over SFTP did not land byte-for-byte in the backing S3 bucket"


def _connect_sftp(hostname, username, pkey, timeout_s: float):
    import socket

    import paramiko

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            transport = paramiko.Transport((hostname, 22))  # customer-built AWS host
            transport.connect(username=username, pkey=pkey)
            return transport
        except (socket.error, paramiko.SSHException, EOFError) as exc:
            last_exc = exc
            time.sleep(10)
    raise AssertionError(f"could not establish SFTP session to {hostname} within {timeout_s}s: {last_exc}")


def _wait_for_server_state(transfer, server_id: str, target_state: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state == target_state:
            return
        if state.endswith("_FAILED"):
            raise AssertionError(f"server entered failure state {state}")
        time.sleep(10)
    raise AssertionError(f"server never reached {target_state}, last seen {state}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-transfer-e2e-")
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


def _create_transfer_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-e2e-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-access",
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
                ],
            }
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
