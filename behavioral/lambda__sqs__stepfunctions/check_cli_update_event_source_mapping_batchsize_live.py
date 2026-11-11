"""cli-update-event-source-mapping-batchsize-live."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-update-event-source-mapping-batchsize-live"
GROUP = "cli-workflow"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws lambda update-event-source-mapping --batch-size` changes how many SQS records a
    live mapping delivers per invocation: batches observed after the update are larger than
    the batches observed (all size 1) before it."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-esm-src-"), tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    res_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-esm-res-"), tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=res_url))

    role_name = ctx.unique_name("sim2real-esm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="esm-io",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": src_arn},
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
            ],
        }),
    )
    _wait_role_assumable(iam, role_name)

    function_name = ctx.unique_name("sim2real-esm-fn-")
    handler_code = (
        "import json, os\n"
        "import boto3\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    n = len(event.get('Records', []))\n"
        "    sqs.send_message(QueueUrl=os.environ['RESULTS_URL'], MessageBody=json.dumps({'count': n}))\n"
        "    return {'count': n}\n"
    )
    zip_path = _write_zip(handler_code)
    try:
        _create_function_with_retry(
            ctx, lam, function_name, role_arn, zip_path, env={"RESULTS_URL": res_url},
            tags={"sim2real:managed": "true"},
        )
    finally:
        os.unlink(zip_path)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    esm = lam.create_event_source_mapping(
        EventSourceArn=src_arn, FunctionName=function_name, BatchSize=1, Enabled=True,
        Tags={"sim2real:managed": "true"},
    )
    uuid = esm["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _wait_esm_state(lam, uuid, "Enabled")

    # phase 1: batch size 1 -> every invocation report should carry exactly 1 record
    for i in range(3):
        sqs.send_message(QueueUrl=src_url, MessageBody=f"phase1-{i}")
    phase1_counts = _drain_counts(sqs, res_url, expected_total=3, timeout_s=60.0)
    assert phase1_counts, "no invocations observed with BatchSize=1"
    assert max(phase1_counts) == 1, f"expected all batches of size 1, got {phase1_counts}"

    # phase 2: bump batch size + batching window via the CLI, wait for it to take effect
    _run_aws(
        ctx, "lambda", "update-event-source-mapping",
        "--uuid", uuid, "--batch-size", "10", "--maximum-batching-window-in-seconds", "5",
    )
    _wait_esm_state(lam, uuid, "Enabled")

    def _current_batch_size():
        return lam.get_event_source_mapping(UUID=uuid)["BatchSize"]

    _poll_until(_current_batch_size, lambda v: v == 10, timeout_s=30.0, interval_s=2.0)

    entries = [{"Id": str(i), "MessageBody": f"phase2-{i}"} for i in range(10)]
    sqs.send_message_batch(QueueUrl=src_url, Entries=entries)
    phase2_counts = _drain_counts(sqs, res_url, expected_total=10, timeout_s=90.0)
    assert phase2_counts, "no invocations observed after raising BatchSize"
    assert max(phase2_counts) > 1, (
        f"expected at least one batch >1 record after BatchSize update, got {phase2_counts}"
    )
    assert max(phase2_counts) <= 10, f"batch exceeded configured BatchSize=10: {phase2_counts}"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _wait_role_assumable(iam_client, role_name, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam_client.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(2)
    raise AssertionError(f"role {role_name} never became visible")


def _delete_role_fully(iam_client, role_name):
    try:
        for pname in iam_client.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam_client.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam_client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam_client.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _write_zip(handler_code: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def _create_function_with_retry(ctx, lambda_client, name, role_arn, zip_path, env=None, tags=None, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()
    kwargs = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler", Code={"ZipFile": zip_bytes}, Timeout=30, MemorySize=128,
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    if tags is not None:
        kwargs["Tags"] = tags
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lambda_client.create_function(**kwargs)
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return resp["FunctionArn"]
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_function never succeeded: {last_err}")


def _wait_esm_state(lambda_client, uuid, want_state, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lambda_client.get_event_source_mapping(UUID=uuid)["State"]
        if last == want_state:
            return
        time.sleep(2)
    raise AssertionError(f"event source mapping never reached {want_state}, last={last}")


def _drain_counts(sqs_client, results_url, expected_total, timeout_s=60.0):
    counts: list[int] = []
    total = 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and total < expected_total:
        resp = sqs_client.receive_message(QueueUrl=results_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            counts.append(body["count"])
            total += body["count"]
            sqs_client.delete_message(QueueUrl=results_url, ReceiptHandle=msg["ReceiptHandle"])
    return counts


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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
