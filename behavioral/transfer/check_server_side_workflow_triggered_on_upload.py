"""server-side-workflow-triggered-on-upload."""
from __future__ import annotations

import io
import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-workflow-triggered-on-upload"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A workflow attached to a server's OnUpload event is automatically invoked by the managed
    service when a real SFTP upload completes -- with no explicit execution-start call from the
    test -- and its TAG step's effect (a tag on the uploaded S3 object) is observably applied."""
    try:
        import paramiko
    except ImportError as exc:

        raise AssertionError(f"paramiko not installed ({exc}); needed for a native SFTP upload to trigger OnUpload")

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    marker = uuid.uuid4().hex
    execution_role_arn = _create_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectTagging", "s3:PutObjectTagging"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
        "sim2real-transfer-onupload-exec-role-",
    )
    user_role_arn = _create_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
        "sim2real-transfer-onupload-user-role-",
    )

    workflow_id = transfer.create_workflow(
        Steps=[
            {
                "Type": "TAG",
                "TagStepDetails": {
                    "Name": "auto-tag",
                    "Tags": [{"Key": "sim2real-workflow-marker", "Value": marker}],
                },
            }
        ]
    )["WorkflowId"]
    ctx.on_cleanup(lambda: transfer.delete_workflow(WorkflowId=workflow_id))

    # CreateServer validates that ExecutionRole is assumable by transfer.amazonaws.com, which
    # fails until the role just created above has propagated -- there is no API to poll for
    # "this role is now assumable", so the bounded retry on the propagation error codes IS the
    # wait; there is no fixed sleep standing in for it.
    server_id = _retry_on_iam_propagation(
        lambda: transfer.create_server(
            Protocols=["SFTP"],
            IdentityProviderType="SERVICE_MANAGED",
            Domain="S3",
            EndpointType="PUBLIC",
            WorkflowDetails={"OnUpload": [{"WorkflowId": workflow_id, "ExecutionRole": execution_role_arn}]},
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-onupload-srv-")}],
        )["ServerId"]
    )
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    transfer.start_server(ServerId=server_id)
    _wait_for_server_state(transfer, server_id, "ONLINE", timeout_s=300)

    key = paramiko.RSAKey.generate(2048)
    username = ctx.unique_name("sim2realonupload")
    _retry_on_iam_propagation(
        lambda: transfer.create_user(
            ServerId=server_id,
            UserName=username,
            Role=user_role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory=f"/{bucket}",
            SshPublicKeyBody=f"{key.get_name()} {key.get_base64()}",
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))

    hostname = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    object_key = "auto-tag-trigger.txt"
    # Measured on real AWS: DescribeServer reports ONLINE well before the endpoint's DNS record
    # resolves and the SSH listener answers -- a 180s budget timed out on "Name or service not
    # known" on the first real replay. 420s is the same margin an adjacent check already proved
    # sufficient.
    transport = _connect_sftp(hostname, username, key, timeout_s=420)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.putfo(io.BytesIO(f"payload-{uuid.uuid4().hex}".encode("utf-8")), object_key)
        sftp.close()
    finally:
        transport.close()

    # We never called any execution-start API: the managed service must invoke the workflow by
    # itself. Poll for the workflow's observable side effect (the TAG step's tag on the object).
    tag_value = _poll_for_tag(s3, bucket, object_key, "sim2real-workflow-marker", timeout_s=120)
    assert tag_value == marker, f"expected auto-applied tag value {marker!r}, got {tag_value!r}"


def _retry_on_iam_propagation(fn, *, attempts: int = 10, delay_s: float = 8.0):
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


def _poll_for_tag(s3, bucket: str, key: str, tag_key: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tags = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key).get("TagSet", [])}
        if tag_key in tags:
            return tags[tag_key]
        time.sleep(3)
    raise AssertionError(f"tag {tag_key!r} never appeared on s3://{bucket}/{key} within {timeout_s}s -- "
                         "workflow was never auto-triggered on upload")


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
    bucket = ctx.unique_name("sim2real-transfer-onupload-")
    kwargs = {}
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint --
    # this follows ctx.region, it does not pin one.
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


def _create_role(ctx, statements: list, name_prefix: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name, PolicyName="inline", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
