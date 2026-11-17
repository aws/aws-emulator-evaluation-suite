"""describe-execution-not-found."""
from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "describe-execution-not-found"
GROUP = 'error-semantics'
SERVICES = ['transfer']

_BOGUS_EXECUTION_ID = '00000000-0000-0000-0000-000000000000'


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DescribeExecution returns the IN_PROGRESS execution that a real SFTP upload started on a workflow with a pending
    custom step, and fails with ResourceNotFoundException "Unknown execution" for a fabricated ExecutionId on that same
    workflow."""
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client("transfer")

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)

    bucket = ctx.unique_name("sim2real-behav-dxnf-").lower()
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
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["ServerId"]
    )
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    transfer.start_server(ServerId=server_id)
    _wait_for_server_state(ctx, server_id, {"ONLINE"}, timeout_s=300)

    user_name = "sim2realdescnf"
    transfer.create_user(
        ServerId=server_id,
        UserName=user_name,
        Role=user_role_arn,
        HomeDirectory=f"/{bucket}",
        HomeDirectoryType="PATH",
        SshPublicKeyBody=pub,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    host = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    _wait_for_ssh_banner(host, timeout_s=420.0)

    local_up = os.path.join(workdir, "trigger.txt")
    with open(local_up, "wb") as fh:
        fh.write(b"sim2real describe-execution-not-found trigger\n")
    up_rc, _, up_err = _sftp(ctx, workdir, host, user_name, priv, [f"put {local_up} trigger.txt", "quit"])
    assert up_rc == 0, f"sftp put exited {up_rc!r}: {up_err[-600:]!r}"

    message = _wait_for_sqs_message(ctx, queue_url, timeout_s=120)
    token = message["token"]
    execution_details = message["serviceMetadata"]["executionDetails"]
    real_workflow_id = execution_details["workflowId"]
    real_execution_id = execution_details["executionId"]
    assert real_workflow_id == workflow_id, (
        f"relay event named workflow {real_workflow_id!r}, expected the one this check created {workflow_id!r}"
    )

    # Positive control: the real execution is still pending (its CUSTOM step has not been signaled)
    # so DescribeExecution must find it. Without this, "not found for a bogus id" is
    # indistinguishable from "DescribeExecution always fails on this workflow" (e.g. a permission or
    # wiring problem).
    control = transfer.describe_execution(WorkflowId=workflow_id, ExecutionId=real_execution_id)
    assert control["Execution"]["ExecutionId"] == real_execution_id, (
        f"expected positive control to describe {real_execution_id!r}, "
        f"got {control.get('Execution', {}).get('ExecutionId')!r}"
    )
    assert control["Execution"]["Status"] == "IN_PROGRESS", (
        f"expected the un-signaled execution to still be IN_PROGRESS, got {control['Execution']['Status']!r}"
    )

    # Negative, on the SAME live workflow: an ExecutionId that was never created is rejected
    # with the specific not-found code, not merely "some error".
    code, message = _error_code(
        lambda: transfer.describe_execution(WorkflowId=workflow_id, ExecutionId=_BOGUS_EXECUTION_ID)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Unknown execution", f"expected 'Unknown execution', got {message!r}"

    # Let the real execution finish cleanly rather than abandoning it to its 300s CUSTOM-step
    # timeout.
    transfer.send_workflow_step_state(
        WorkflowId=workflow_id, ExecutionId=real_execution_id, Token=token, Status="SUCCESS"
    )


def _error_code(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises rather than
    returning a falsy sentinel -- an over-permissive target accepting a bogus ExecutionId is the
    strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected DescribeExecution to be rejected, but it succeeded and returned {result!r}")


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


def _workdir(ctx) -> str:
    """A private scratch dir for this run. Never a fixed /tmp path: the host may run other checks
    at once, and a predictable name lets one run overwrite another's private key."""
    path = tempfile.mkdtemp(prefix='sim2real-transfer-dxnf-')
    ctx.on_cleanup(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


def _keygen(workdir: str, stem: str = 'sim2real-key') -> tuple[str, str]:
    """Generate an RSA keypair with the real ssh-keygen. Returns (private path, public body)."""
    priv = os.path.join(workdir, stem)
    proc = subprocess.run(
        ['/usr/bin/ssh-keygen', '-q', '-t', 'rsa', '-b', '3072', '-m', 'PEM',
         '-N', '', '-C', 'sim2real', '-f', priv],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"ssh-keygen failed: {proc.stdout!r} {proc.stderr!r}"
    os.chmod(priv, 0o600)
    return priv, open(priv + '.pub').read().strip()


def _sftp(ctx, workdir: str, host: str, user: str, priv: str, lines, *, timeout_s=180.0):
    """One non-interactive session through /usr/bin/sftp -- the real OpenSSH client."""
    batch = os.path.join(workdir, 'batch.sftp')
    with open(batch, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    argv = ['/usr/bin/sftp', '-b', batch, '-i', priv,
            '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'BatchMode=yes',
            '-o', 'NumberOfPasswordPrompts=0',
            '-o', 'PreferredAuthentications=publickey',
            '-o', 'ConnectTimeout=30',
            f'{user}@{host}']
    socket.getaddrinfo(host, 22)  # customer-built AWS host
    proc = subprocess.run(argv, env=ctx.subprocess_env(), cwd=workdir,  # customer-built AWS host
                          capture_output=True, text=True, timeout=timeout_s)
    return proc.returncode, proc.stdout, proc.stderr


def _wait_for_ssh_banner(host: str, *, timeout_s: float, interval_s: float = 10.0) -> bytes:
    """Poll TCP 22 until the server sends an SSH identification string. DescribeServer reporting
    ONLINE is the control plane's claim; the banner is the only evidence the endpoint actually
    terminates SSH."""
    deadline = time.monotonic() + timeout_s
    last = 'never attempted'
    while True:
        try:
            sock = socket.create_connection((host, 22), timeout=20.0)  # customer-built AWS host
            try:
                sock.settimeout(20.0)
                banner = sock.recv(255)
            finally:
                sock.close()
            if banner.startswith(b'SSH-2.0-'):
                return banner
            last = f'banner {banner!r}'
        except OSError as exc:
            last = f'{type(exc).__name__}: {exc}'
        if time.monotonic() >= deadline:
            raise AssertionError(f"{host}:22 never spoke SSH within {timeout_s}s; last attempt: {last}")
        time.sleep(interval_s)


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dxnf-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.tag_queue(QueueUrl=url, Tags={"sim2real": CHECK})
    return url


def _create_role(ctx, kind: str, principal: str, inline_policy: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-dxnf-{kind}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
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

    func_name = ctx.unique_name("sim2real-behav-dxnf-relay-")
    ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
    func_arn = _retry_on_access_denied(
        lambda: lambda_client.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            Environment={"Variables": {"QUEUE_URL": queue_url}},
            Tags={"sim2real": CHECK},
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


def _wait_for_sqs_message(ctx, queue_url: str, timeout_s: float = 120.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return json.loads(msg["Body"])
    raise AssertionError(f"no relay message arrived on {queue_url} within {timeout_s}s")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
