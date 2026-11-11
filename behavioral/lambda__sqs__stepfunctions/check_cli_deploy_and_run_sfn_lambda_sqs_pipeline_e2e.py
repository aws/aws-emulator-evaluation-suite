"""cli-deploy-and-run-sfn-lambda-sqs-pipeline-e2e."""
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

CHECK = "cli-deploy-and-run-sfn-lambda-sqs-pipeline-e2e"
GROUP = "cli-workflow"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws-cli driven creation of an IAM role, a Lambda function, a Step Functions state
    machine, and StartExecution is verified end-to-end by reading the resulting SQS message
    (sent by the Lambda) via the boto3 SDK."""
    require_tools("aws")

    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    sfn = ctx.client("stepfunctions")

    queue_name = ctx.unique_name("sim2real-e2e-q-")
    lambda_role_name = ctx.unique_name("sim2real-e2e-lrole-")
    sfn_role_name = ctx.unique_name("sim2real-e2e-srole-")
    function_name = ctx.unique_name("sim2real-e2e-fn-")
    sm_name = ctx.unique_name("sim2real-e2e-sm-")

    # 1. queue, via CLI
    queue_url = _run_aws(ctx, "sqs", "create-queue", "--queue-name", queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: _run_aws(ctx, "sqs", "delete-queue", "--queue-url", queue_url, check=False))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # 2. lambda execution role, via CLI
    lambda_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    lambda_role_arn = _run_aws(
        ctx, "iam", "create-role", "--role-name", lambda_role_name,
        "--assume-role-policy-document", lambda_trust,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(ctx, iam, lambda_role_name))
    _run_aws(
        ctx, "iam", "attach-role-policy", "--role-name", lambda_role_name,
        "--policy-arn", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    lambda_inline = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    })
    _run_aws(
        ctx, "iam", "put-role-policy", "--role-name", lambda_role_name,
        "--policy-name", "send-to-queue", "--policy-document", lambda_inline,
    )
    _wait_role_assumable(iam, lambda_role_name)

    # 3. lambda function, via CLI (zip built locally, uploaded with --zip-file fileb://)
    handler_code = (
        "import json, os\n"
        "import boto3\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps({'received': event}))\n"
        "    return {'status': 'sent'}\n"
    )
    zip_path = _write_zip(handler_code)
    try:
        function_arn = _run_aws_retry(
            ctx, [
                "lambda", "create-function",
                "--function-name", function_name,
                "--runtime", "python3.12",
                "--role", lambda_role_arn,
                "--handler", "lambda_function.handler",
                "--zip-file", f"fileb://{zip_path}",
                "--timeout", "30",
                "--environment", json.dumps({"Variables": {"QUEUE_URL": queue_url}}),
            ],
            timeout_s=90.0,
        )["FunctionArn"]
    finally:
        os.unlink(zip_path)
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", function_name, check=False))
    ctx.client("lambda").get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # 4. step functions role, via CLI
    sfn_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    sfn_role_arn = _run_aws(
        ctx, "iam", "create-role", "--role-name", sfn_role_name,
        "--assume-role-policy-document", sfn_trust,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(ctx, iam, sfn_role_name))
    sfn_inline = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn}],
    })
    _run_aws(
        ctx, "iam", "put-role-policy", "--role-name", sfn_role_name,
        "--policy-name", "invoke-lambda", "--policy-document", sfn_inline,
    )
    _wait_role_assumable(iam, sfn_role_name)

    # 5. state machine, via CLI
    definition = json.dumps({
        "Comment": "sim2real e2e pipeline",
        "StartAt": "Invoke",
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": function_arn,
                "Retry": [
                    {"ErrorEquals": ["States.ALL"], "IntervalSeconds": 2, "MaxAttempts": 6, "BackoffRate": 2.0}
                ],
                "End": True,
            }
        },
    })
    sm_arn = _run_aws_retry(
        ctx, [
            "stepfunctions", "create-state-machine",
            "--name", sm_name,
            "--definition", definition,
            "--role-arn", sfn_role_arn,
        ],
        timeout_s=60.0,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # 6. start-execution, via CLI
    marker = ctx.unique_name("marker-")
    exec_arn = _run_aws(
        ctx, "stepfunctions", "start-execution",
        "--state-machine-arn", sm_arn,
        "--input", json.dumps({"marker": marker}),
    )["executionArn"]

    def _describe():
        return sfn.describe_execution(executionArn=exec_arn)

    result = _poll_until(_describe, lambda r: r["status"] != "RUNNING", timeout_s=90.0, interval_s=3.0)
    assert result["status"] == "SUCCEEDED", f"execution ended in {result['status']}: {result.get('error')}"

    # 7. verify the Lambda's side effect landed on the queue, via SDK
    messages: list[dict] = []
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and not messages:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
    assert messages, "lambda did not deliver a message to the queue"
    body = json.loads(messages[0]["Body"])
    assert body["received"]["marker"] == marker, (
        f"queue message marker mismatch: expected {marker!r}, got {body['received'].get('marker')!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])


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


def _run_aws_retry(ctx, args, timeout_s=90.0, interval_s=3.0):
    """Retries an aws-cli call while IAM role trust propagates to lambda/states (eventually
    consistent for tens of seconds after CreateRole)."""
    deadline = time.monotonic() + timeout_s
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=30.0, check=False)
        if proc.returncode == 0:
            out = proc.stdout.strip()
            if not out:
                return {}
            try:
                return json.loads(out)
            except (json.JSONDecodeError, ValueError):
                return out
        last_err = proc.stderr
        time.sleep(interval_s)
    raise AssertionError(f"aws cli command never succeeded: {args}\nlast stderr: {last_err}")


def _wait_role_assumable(iam_client, role_name, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam_client.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(2)
    raise AssertionError(f"role {role_name} never became visible")


def _delete_role_fully(ctx, iam_client, role_name):
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
