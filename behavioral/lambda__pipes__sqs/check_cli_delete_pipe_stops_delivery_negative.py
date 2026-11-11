"""cli-delete-pipe-stops-delivery-negative."""
from __future__ import annotations

import io
import json
import subprocess
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-delete-pipe-stops-delivery-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]

_FORWARD_CODE = """
import json
import os

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]


def handler(event, context):
    bodies = [record.get("body") for record in event]
    _sqs.send_message(
        QueueUrl=_RESULTS_URL,
        MessageBody=json.dumps({"bodies": bodies, "count": len(event)}),
    )
    return {"batchItemFailures": []}
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A message sent while the pipe is RUNNING reaches the Lambda target, while one sent after `aws
    pipes delete-pipe` (DescribePipe then NotFoundException) is never delivered and can still be
    received from the source queue."""
    require_tools("aws")

    visibility_timeout = 10
    source = _create_queue(ctx, "sim2real-cp3-src-", attributes={"VisibilityTimeout": str(visibility_timeout)})
    results = _create_queue(ctx, "sim2real-cp3-res-")

    lambda_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-cp3-fn-"), lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results["url"]}
    )

    pipe_role = _create_pipe_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            },
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn},
        ],
    )

    pipe_name = ctx.unique_name("sim2real-cp3-pipe-")
    _create_pipe_via_cli_and_wait_running(
        ctx,
        pipe_name,
        role_arn=pipe_role,
        source_arn=source["arn"],
        target_arn=fn_arn,
        source_parameters={"SqsQueueParameters": {"BatchSize": 1}},
        target_parameters={"LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}},
    )

    sqs = ctx.client("sqs")

    # --- positive control: the pipe is RUNNING, delivery works ---
    body_before = f"before-delete-{pipe_name}"
    sqs.send_message(QueueUrl=source["url"], MessageBody=body_before)
    delivered = _poll_until(
        lambda: _drain_json_messages(ctx, results["url"]),
        lambda msgs: any(body_before in m.get("bodies", []) for m in msgs),
        timeout_s=90,
        interval_s=3,
    )
    assert any(body_before in m.get("bodies", []) for m in delivered), "positive control: pipe must deliver while RUNNING"

    # --- break exactly one thing: delete the pipe via the CLI ---
    _run_shell(ctx, ["aws", "--output", "json", "pipes", "delete-pipe", "--name", pipe_name])
    deadline = time.monotonic() + 60
    pipes = ctx.client("pipes")
    gone = False
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=pipe_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                gone = True
                break
            raise
        time.sleep(2)
    assert gone, f"pipe {pipe_name} was not actually removed by delete-pipe"

    # --- effect absent: a message sent after deletion is never delivered ... ---
    body_after = f"after-delete-{pipe_name}"
    sqs.send_message(QueueUrl=source["url"], MessageBody=body_after)
    observe_deadline = time.monotonic() + max(45, visibility_timeout * 4)
    delivered_after: set[str] = set()
    while time.monotonic() < observe_deadline:
        for m in _drain_json_messages(ctx, results["url"], wait_s=3):
            delivered_after.update(m.get("bodies", []))
        if body_after in delivered_after:
            break
        time.sleep(3)
    assert body_after not in delivered_after, "a deleted pipe must never deliver further messages"

    # --- ... and remains redeliverable on the source queue (never silently consumed) ---
    got_back = False
    redeliver_deadline = time.monotonic() + 60
    while time.monotonic() < redeliver_deadline and not got_back:
        resp = sqs.receive_message(
            QueueUrl=source["url"], MaxNumberOfMessages=1, WaitTimeSeconds=10, VisibilityTimeout=5
        )
        for m in resp.get("Messages", []):
            if m.get("Body") == body_after:
                got_back = True
    assert got_back, "message sent after delete-pipe must remain on the source queue, unconsumed"


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


def _run_aws_with_retry(ctx, args, timeout_s=150.0, retry_interval_s=5.0):
    """Run an aws CLI command, retrying on failure (IAM role propagation delay) until it
    succeeds or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    last_stderr = ""
    while True:
        proc = _run_shell(ctx, ["aws", "--output", "json", *args], check=False, timeout_s=30.0)
        if proc.returncode == 0:
            if not proc.stdout.strip():
                return {}
            try:
                return json.loads(proc.stdout)
            except (json.JSONDecodeError, ValueError):
                return proc.stdout.strip()
        last_stderr = proc.stderr
        if time.monotonic() >= deadline:
            raise AssertionError(f"aws {' '.join(args[:2])} failed after retries: {last_stderr[-500:]}")
        time.sleep(retry_interval_s)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_queue(ctx, prefix, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"QueueName": name}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_json_messages(ctx, queue_url, max_messages=10, wait_s=3):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s)
    for m in resp.get("Messages", []):
        try:
            body = json.loads(m["Body"])
        except (json.JSONDecodeError, ValueError):
            body = m["Body"]
        out.append(body)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _make_lambda_zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp3-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-cp3-lpolicy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp3-prole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if statements:
        policy_name = ctx.unique_name("sim2real-cp3-ppolicy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_lambda_function(ctx, name, role_arn, code, env=None, timeout=30):
    lam = ctx.client("lambda")
    zip_bytes = _make_lambda_zip(code)
    deadline = time.monotonic() + 90
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"lambda function {name} could not be created: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _poll_pipe_state(ctx, name, terminal_states, timeout_s=90, interval_s=3):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    state, reason = None, ""
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        state = desc.get("CurrentState")
        reason = desc.get("StateReason", "")
        if state in terminal_states:
            return state, reason
        time.sleep(interval_s)
    return state, reason


def _delete_pipe_and_wait(ctx, name, timeout_s=60):
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2)


def _create_pipe_via_cli_and_wait_running(
    ctx, name, *, role_arn, source_arn, target_arn, source_parameters=None, target_parameters=None, timeout_s=150
):
    ctx.on_cleanup(lambda: _delete_pipe_and_wait(ctx, name))
    args = [
        "pipes", "create-pipe",
        "--name", name,
        "--role-arn", role_arn,
        "--source", source_arn,
        "--target", target_arn,
        "--desired-state", "RUNNING",
    ]
    if source_parameters:
        args += ["--source-parameters", json.dumps(source_parameters)]
    if target_parameters:
        args += ["--target-parameters", json.dumps(target_parameters)]
    _run_aws_with_retry(ctx, args, timeout_s=timeout_s)
    state, reason = _poll_pipe_state(ctx, name, {"RUNNING", "CREATE_FAILED", "START_FAILED"}, timeout_s=timeout_s)
    if state != "RUNNING":
        raise AssertionError(f"pipe {name} never reached RUNNING (state={state}, reason={reason})")


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
