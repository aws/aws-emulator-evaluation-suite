"""cli-purge-queue-then-esm-no-messages-processed-negative."""
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

CHECK = "cli-purge-queue-then-esm-no-messages-processed-negative"
GROUP = "cli-workflow"
SERVICES = ["lambda", "stepfunctions", "sqs"]
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Messages purged while the queue's event source mapping is disabled produce no invocation once
    it is enabled, while a message sent after the purge is processed."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    src_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-purge-src-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    res_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-purge-res-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=res_url))

    role_name = ctx.unique_name("sim2real-purge-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
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

    function_name = ctx.unique_name("sim2real-purge-fn-")
    handler_code = (
        "import json, os\n"
        "import boto3\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    bodies = [r['body'] for r in event.get('Records', [])]\n"
        "    sqs.send_message(QueueUrl=os.environ['RESULTS_URL'], MessageBody=json.dumps({'bodies': bodies}))\n"
        "    return {'n': len(bodies)}\n"
    )
    zip_path = _write_zip(handler_code)
    try:
        _ = _create_function_with_retry(lam, function_name, role_arn, zip_path, env={"RESULTS_URL": res_url}, tags=_TAGS)
    finally:
        os.unlink(zip_path)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    # ESM created disabled: the poller must never see the messages we're about to purge.
    esm = lam.create_event_source_mapping(
        EventSourceArn=src_arn, FunctionName=function_name, BatchSize=5, Enabled=False, Tags=_TAGS
    )
    uuid = esm["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _wait_esm_state(lam, uuid, "Disabled")

    for i in range(5):
        sqs.send_message(QueueUrl=src_url, MessageBody=f"to-be-purged-{i}")
    _poll_until(
        lambda: int(sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"]),
        lambda n: n >= 5, timeout_s=30.0, interval_s=2.0,
    )

    # break: purge via the CLI while nothing is consuming
    _run_aws(ctx, "sqs", "purge-queue", "--queue-url", src_url)

    # SQS documents the purge as taking up to 60s to fully process.
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html
    def _total_remaining():
        attrs = sqs.get_queue_attributes(
            QueueUrl=src_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])

    _poll_until(_total_remaining, lambda n: n == 0, timeout_s=90.0, interval_s=5.0)

    lam.update_event_source_mapping(UUID=uuid, Enabled=True)
    _wait_esm_state(lam, uuid, "Enabled")

    # assert: no invocation is produced for the purged batch
    deadline = time.monotonic() + 30.0
    leftover = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=res_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        leftover.extend(resp.get("Messages", []))
        if leftover:
            break
    assert not leftover, f"lambda was invoked for purged messages: {[m['Body'] for m in leftover]}"

    # positive control: the mapping still works for messages sent after the purge
    sqs.send_message(QueueUrl=src_url, MessageBody="post-purge-message")
    control = []
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline and not control:
        resp = sqs.receive_message(QueueUrl=res_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        control = resp.get("Messages", [])
    assert control, "positive control: mapping never invoked lambda for a message sent after the purge"
    body = json.loads(control[0]["Body"])
    assert "post-purge-message" in body["bodies"], (
        f"expected 'post-purge-message' among invoked bodies, got {body['bodies']}"
    )


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


def _create_function_with_retry(lambda_client, name, role_arn, zip_path, env=None, tags=None, timeout_s=90.0):
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
