"""cli-recreate-queue-changes-arn-stale-esm-negative."""
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

CHECK = "cli-recreate-queue-changes-arn-stale-esm-negative"
GROUP = "cli-workflow"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue recreated under a new name has a different ARN: the event source mapping still
    bound to the deleted queue's ARN never delivers the replacement queue's messages, while a
    fresh mapping bound to the new ARN does (positive control)."""
    require_tools("aws")

    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    q1_name = ctx.unique_name("sim2real-recreate-q1-")
    q1_url = sqs.create_queue(QueueName=q1_name)["QueueUrl"]
    q1_arn = sqs.get_queue_attributes(QueueUrl=q1_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-recreate-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="esm-io",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": "arn:aws:sqs:*:*:sim2real-recreate-*"},
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
            ],
        }),
    )
    _wait_role_assumable(iam, role_name)

    function_name = ctx.unique_name("sim2real-recreate-fn-")
    res_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-recreate-res-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=res_url))
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
        _ = _create_function_with_retry(lam, function_name, role_arn, zip_path, env={"RESULTS_URL": res_url})
    finally:
        os.unlink(zip_path)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    stale_esm = lam.create_event_source_mapping(EventSourceArn=q1_arn, FunctionName=function_name, BatchSize=5, Enabled=True)
    stale_uuid = stale_esm["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=stale_uuid))
    _wait_esm_state(lam, stale_uuid, "Enabled")

    # sanity: the mapping works against Q1 before we delete it
    sqs.send_message(QueueUrl=q1_url, MessageBody="pre-delete-sanity")
    sanity = _drain(sqs, res_url, timeout_s=60.0)
    assert sanity, "sanity check failed: mapping never invoked lambda for the original queue"

    # delete Q1 via the CLI
    _run_aws(ctx, "sqs", "delete-queue", "--queue-url", q1_url)
    _poll_until(
        lambda: _queue_exists(sqs, q1_url), lambda exists: not exists, timeout_s=90.0, interval_s=5.0,
    )

    # "recreate" as a distinct resource under a new name via the CLI -> guaranteed new ARN
    # (SQS ARNs are arn:aws:sqs:<region>:<account>:<name>, and DeleteQueue enforces a same-name
    # reuse cooldown: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteQueue.html)
    q2_name = ctx.unique_name("sim2real-recreate-q2-")
    q2_url = _run_aws(ctx, "sqs", "create-queue", "--queue-name", q2_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q2_url))
    q2_arn = sqs.get_queue_attributes(QueueUrl=q2_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert q2_arn != q1_arn, "expected the replacement queue to have a different ARN"

    # break: the old mapping still targets the (now-deleted) Q1 ARN; messages on Q2 are invisible to it
    sqs.send_message(QueueUrl=q2_url, MessageBody="post-recreate-message")
    leftover = _drain(sqs, res_url, timeout_s=30.0)
    assert not leftover, f"stale mapping unexpectedly invoked lambda for the new queue: {leftover}"

    # positive control: a fresh mapping bound to Q2's real ARN does invoke Lambda. Drain any
    # leftover "post-recreate-message" still sitting unconsumed in Q2 first, so the control
    # signal isn't masked by that earlier message being the one that lands in res_url.
    while True:
        resp = sqs.receive_message(QueueUrl=q2_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        if not resp.get("Messages"):
            break
        for msg in resp["Messages"]:
            sqs.delete_message(QueueUrl=q2_url, ReceiptHandle=msg["ReceiptHandle"])

    fresh_esm = lam.create_event_source_mapping(EventSourceArn=q2_arn, FunctionName=function_name, BatchSize=5, Enabled=True)
    fresh_uuid = fresh_esm["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=fresh_uuid))
    _wait_esm_state(lam, fresh_uuid, "Enabled")
    sqs.send_message(QueueUrl=q2_url, MessageBody="post-recreate-message-2")
    control = _drain(sqs, res_url, timeout_s=60.0)
    assert control, "positive control: fresh mapping on the new ARN never invoked lambda"
    control_bodies = [json.loads(m["Body"])["bodies"] for m in control]
    assert any("post-recreate-message-2" in bodies for bodies in control_bodies), (
        f"expected 'post-recreate-message-2' among delivered bodies, got: {control_bodies}"
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


def _create_function_with_retry(lambda_client, name, role_arn, zip_path, env=None, timeout_s=90.0):
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


def _queue_exists(sqs_client, queue_url) -> bool:
    try:
        sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        return True
    except Exception:
        return False


def _drain(sqs_client, queue_url, timeout_s=60.0):
    out = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not out:
        resp = sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


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
