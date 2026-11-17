"""send-workflow-step-state-out-of-order-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import TYPE_CHECKING

from behavioral_harness import tags

if TYPE_CHECKING:
    # Annotation-only import: the runtime imports live in the helpers below, behind the
    # paramiko availability probe in run(), which raises (never skips) if paramiko is absent.
    import paramiko

CHECK = "send-workflow-step-state-out-of-order-rejected"
GROUP = "ordering"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """After a real SFTP upload's custom workflow step is reported SUCCESS and the execution retires, replaying the same
    step token fails with ResourceNotFoundException "Unknown execution", and DescribeExecution still reports the
    execution unknown with the same message."""
    # paramiko drives the real SFTP upload; a missing module propagates as the runner's ImportError.
    import paramiko  # noqa: F401

    transfer = ctx.client("transfer")

    bucket = ctx.unique_name("sim2real-behav-wf-").lower()
    _create_bucket(ctx, bucket)

    queue_url = _create_queue(ctx)
    queue_arn = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    lambda_arn = _create_relay_lambda(ctx, queue_url, queue_arn)
    workflow_role_arn = _create_role(
        ctx,
        "wfrole",
        "transfer.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": lambda_arn}],
        },
    )
    workflow_id = transfer.create_workflow(
        Steps=[
            {
                "Type": "CUSTOM",
                "CustomStepDetails": {"Name": "relay-token", "Target": lambda_arn, "TimeoutSeconds": 300},
            }
        ]
    )["WorkflowId"]
    ctx.on_cleanup(lambda: transfer.delete_workflow(WorkflowId=workflow_id))

    user_role_arn = _create_role(
        ctx,
        "userrole",
        "transfer.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
    )

    server_id = _retry_on_access_denied(
        lambda: transfer.create_server(
            Protocols=["SFTP"],
            IdentityProviderType="SERVICE_MANAGED",
            WorkflowDetails={"OnUpload": [{"WorkflowId": workflow_id, "ExecutionRole": workflow_role_arn}]},
        )["ServerId"]
    )
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.start_server(ServerId=server_id)
    _wait_for_server_state(ctx, server_id, {"ONLINE"}, timeout_s=300)

    user_name = "sim2realwftest"
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=user_role_arn,
        HomeDirectory=f"/{bucket}",
        HomeDirectoryType="PATH",
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    public_key_body, private_key = _generate_ed25519_keypair()
    ssh_key_id = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=user_name, SshPublicKeyBody=public_key_body
    )["SshPublicKeyId"]
    ctx.on_cleanup(
        lambda: transfer.delete_ssh_public_key(
            ServerId=server_id, SshPublicKeyId=ssh_key_id, UserName=user_name
        )
    )

    endpoint = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    _upload_via_sftp(private_key, "trigger.txt", b"sim2real workflow trigger payload\n", user_name, endpoint)


    message = _wait_for_sqs_message(ctx, queue_url, timeout_s=120)
    token = message["token"]
    execution_details = message["serviceMetadata"]["executionDetails"]
    workflow_id_from_event = execution_details["workflowId"]
    execution_id = execution_details["executionId"]
    assert workflow_id_from_event == workflow_id

    # First (correct, currently-pending) report of this step's state: succeeds.
    transfer.send_workflow_step_state(
        WorkflowId=workflow_id, ExecutionId=execution_id, Token=token, Status="SUCCESS"
    )

    # Positive control: the execution actually retires (DescribeExecution stops
    # resolving it) rather than getting stuck IN_PROGRESS or landing in EXCEPTION.
    _wait_for_execution_retired(ctx, workflow_id, execution_id, timeout_s=30)

    # Replaying the *same* token now that the execution has already retired must be
    # rejected rather than silently re-accepted or allowed to re-drive anything.
    code, message = _error_code(
        lambda: transfer.send_workflow_step_state(
            WorkflowId=workflow_id, ExecutionId=execution_id, Token=token, Status="SUCCESS"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unknown execution", f"expected 'Unknown execution', got {message!r}"

    # Effect absent: the stale replay did not resurrect or otherwise perturb the
    # retired execution -- an independent read (DescribeExecution, not the mutating
    # SendWorkflowStepState call) still finds it unknown.
    code_after_replay, message_after_replay = _error_code(
        lambda: transfer.describe_execution(WorkflowId=workflow_id, ExecutionId=execution_id)
    )
    assert code_after_replay == "ResourceNotFoundException", (
        f"expected the retired execution to remain unknown to DescribeExecution, got {code_after_replay}"
    )
    assert message_after_replay == "Unknown execution", (
        f"expected 'Unknown execution', got {message_after_replay!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_on_access_denied(fn, timeout_s: float = 30.0, interval_s: float = 3.0):
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


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-wf-tok-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _create_role(ctx, kind: str, principal: str, inline_policy: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-{kind}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-inline"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_relay_lambda(ctx, queue_url: str, queue_arn: str) -> str:
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")

    role_arn = _create_role(
        ctx,
        "lambdarole",
        "lambda.amazonaws.com",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]},
    )
    iam.attach_role_policy(
        RoleName=role_arn.split("/")[-1],
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_arn.split("/")[-1],
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )

    code = (
        "import json, os, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
        "    return {'statusCode': 200}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)

    func_name = ctx.unique_name("sim2real-behav-wf-relay-")
    func_arn = _retry_on_access_denied(
        lambda: lambda_client.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            Environment={"Variables": {"QUEUE_URL": queue_url}},
        )["FunctionArn"]
    )
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=func_name))
    return func_arn


def _wait_for_server_state(ctx, server_id: str, target_states: set, timeout_s: float = 300.0) -> str:
    transfer = ctx.client("transfer")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state in target_states:
            return state
        time.sleep(5)
    raise AssertionError(f"server {server_id} never reached {target_states}, last state {state}")


def _generate_ed25519_keypair() -> tuple[str, "paramiko.Ed25519Key"]:
    """Generate an ed25519 keypair via `cryptography` and load it into a paramiko
    PKey. Unlike RSAKey/ECDSAKey, paramiko's Ed25519Key has no `.generate()` --
    it can only load an existing key, never mint one -- so the raw key material
    comes from `cryptography` (already a hard dependency of paramiko itself, so
    no separate availability guard is needed). Returns the OpenSSH-format public
    key line (for ImportSshPublicKey) and the paramiko PKey usable directly for
    auth."""
    import io

    import paramiko
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    raw_private_key = Ed25519PrivateKey.generate()
    private_pem = raw_private_key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()).decode()
    public_line = raw_private_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    private_key = paramiko.Ed25519Key.from_private_key(io.StringIO(private_pem))
    return public_line, private_key


def _upload_via_sftp(
    private_key: "paramiko.Ed25519Key",
    remote_filename: str,
    content: bytes,
    user_name: str,
    endpoint: str,
    timeout_s: float = 360.0,
) -> None:
    """Upload `content` to `remote_filename` over SFTP using paramiko's
    pure-Python SSH/SFTP client -- no dependency on system ssh/sftp
    binaries. Retries the whole connect+auth+put cycle since the server's
    public endpoint can take a short while to become reachable right after
    StartServer/CreateUser/ImportSshPublicKey."""
    import io as _io

    import paramiko

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        transport = None
        try:
            transport = paramiko.Transport((endpoint, 22))  # customer-built AWS host
            transport.connect(username=user_name, pkey=private_key)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.putfo(_io.BytesIO(content), remote_filename)
            sftp.close()
            return
        except (paramiko.SSHException, OSError) as exc:
            last_error = exc
            time.sleep(2)
        finally:
            if transport is not None:
                transport.close()
    raise AssertionError(f"sftp upload to {endpoint} never succeeded: {last_error}")


def _wait_for_sqs_message(ctx, queue_url: str, timeout_s: float = 120.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return json.loads(msg["Body"])
    raise AssertionError(f"no relay message arrived on {queue_url} within {timeout_s}s")


def _wait_for_execution_retired(ctx, workflow_id: str, execution_id: str, timeout_s: float = 30.0) -> None:
    """Poll DescribeExecution until it stops resolving the execution. Real AWS
    retires a completed single-CUSTOM-step OnUpload execution almost immediately
    -- there is no observable COMPLETED status to wait for, only a brief
    IN_PROGRESS read followed by ResourceNotFoundException.
    A status other than IN_PROGRESS (e.g. EXCEPTION) or a timeout is a real
    failure to raise on, not something to retry past."""
    from botocore.exceptions import ClientError

    transfer = ctx.client("transfer")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = transfer.describe_execution(WorkflowId=workflow_id, ExecutionId=execution_id)[
                "Execution"
            ]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        assert last_status == "IN_PROGRESS", f"execution {execution_id} in unexpected state {last_status!r}"
        time.sleep(1)
    raise AssertionError(
        f"execution {execution_id} never retired from DescribeExecution within {timeout_s}s, "
        f"last status {last_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
