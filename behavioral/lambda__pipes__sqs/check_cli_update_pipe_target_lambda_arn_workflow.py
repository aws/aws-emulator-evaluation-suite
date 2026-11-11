"""cli-update-pipe-target-lambda-arn-workflow."""
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

CHECK = "cli-update-pipe-target-lambda-arn-workflow"
GROUP = "event-propagation"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """`aws pipes update-pipe` changing TargetArn redirects SQS-sourced deliveries: a pre-update
    message lands on the old target's results queue, a post-update message lands only on the new
    one, and the old results queue's ApproximateNumberOfMessages polls to 0."""
    require_tools("aws")

    source = _create_queue(ctx, "sim2real-cp2-src-")
    results_a = _create_queue(ctx, "sim2real-cp2-resa-")
    results_b = _create_queue(ctx, "sim2real-cp2-resb-")

    lambda_role = _create_lambda_role(
        ctx,
        extra_statements=[
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": [results_a["arn"], results_b["arn"]]}
        ],
    )
    fn_a_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-cp2-fna-"), lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results_a["url"]}
    )
    fn_b_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-cp2-fnb-"), lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results_b["url"]}
    )

    pipe_role = _create_pipe_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            },
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": [fn_a_arn, fn_b_arn]},
        ],
    )

    pipe_name = ctx.unique_name("sim2real-cp2-pipe-")
    _create_pipe_via_cli_and_wait_running(
        ctx,
        pipe_name,
        role_arn=pipe_role,
        source_arn=source["arn"],
        target_arn=fn_a_arn,
        source_parameters={"SqsQueueParameters": {"BatchSize": 1}},
        target_parameters={"LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}},
    )

    sqs = ctx.client("sqs")

    # --- before the update: deliveries go to target A ---
    body1 = f"before-update-{pipe_name}"
    t0 = time.monotonic()
    sqs.send_message(QueueUrl=source["url"], MessageBody=body1)
    delivered_a = _poll_until(
        lambda: _drain_json_messages(ctx, results_a["url"]),
        lambda msgs: any(body1 in m.get("bodies", []) for m in msgs),
        timeout_s=90,
        interval_s=3,
        description="delivery of pre-update message to target A",
    )
    latency_a = time.monotonic() - t0
    assert any(body1 in m.get("bodies", []) for m in delivered_a), (
        f"message before update must land on target A; results-A drain was {delivered_a!r}"
    )

    # --- update the pipe's target to Lambda B via the CLI ---
    _run_aws_with_retry(
        ctx,
        [
            "pipes", "update-pipe",
            "--name", pipe_name,
            "--role-arn", pipe_role,
            "--target", fn_b_arn,
            "--target-parameters", json.dumps({"LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}}),
        ],
        timeout_s=90,
    )
    state, reason = _poll_pipe_state(ctx, pipe_name, {"RUNNING", "UPDATE_FAILED"}, timeout_s=90)
    assert state == "RUNNING", f"pipe did not return to RUNNING after update-pipe (state={state}, reason={reason})"
    desc = ctx.client("pipes").describe_pipe(Name=pipe_name)
    assert desc["Target"] == fn_b_arn, f"pipe Target should now be {fn_b_arn}, got {desc['Target']}"

    # --- after the update: deliveries go to target B, never to A again ---
    body2 = f"after-update-{pipe_name}"
    t1 = time.monotonic()
    sqs.send_message(QueueUrl=source["url"], MessageBody=body2)
    delivered_b = _poll_until(
        lambda: _drain_json_messages(ctx, results_b["url"]),
        lambda msgs: any(body2 in m.get("bodies", []) for m in msgs),
        timeout_s=90,
        interval_s=3,
        description="delivery of post-update message to target B",
    )
    latency_b = time.monotonic() - t1
    assert any(body2 in m.get("bodies", []) for m in delivered_b), (
        f"message after update must land on target B; results-B drain was {delivered_b!r}"
    )

    # target A must never see the post-update message: hold absence for >=3x the
    # slower of the two delivery latencies just measured on this same wiring,
    # not a flat guess that could be shorter than genuine delivery time
    leak_window_s = max(3 * max(latency_a, latency_b), 15.0)
    leaked_to_a = _drain_for(ctx, results_a["url"], leak_window_s)
    assert not any(body2 in m.get("bodies", []) for m in leaked_to_a), (
        f"post-update message leaked to the old target during a {leak_window_s:.1f}s window: {leaked_to_a!r}"
    )
    # ApproximateNumberOfMessages can lag up to a minute after the last send/delete
    # (SQS GetQueueAttributes docs), so poll it to zero rather than read it once
    _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=results_a["url"], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"],
        lambda attrs: attrs["ApproximateNumberOfMessages"] == "0",
        timeout_s=90.0,
        budget_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="results-A queue ApproximateNumberOfMessages reaching 0 after the leak window",
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, description="condition", budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait for {description} ended; last observed: {last!r}; not graded"
        )
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed: {last!r}")


_MANAGED_TAG_KEY = "sim2real:managed"
_RESOURCE_PREFIX = "sim2real-cp2-"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _RESOURCE_PREFIX.rstrip("-")}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _resource_tags_cli() -> str:
    return ",".join(f"{k}={v}" for k, v in _resource_tags().items())


def _create_queue(ctx, prefix, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"QueueName": name, "tags": _resource_tags()}
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


def _drain_for(ctx, queue_url, duration_s):
    """Long-poll-drain a queue for the whole window, not just one receive call."""
    deadline = time.monotonic() + duration_s
    out = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        wait_s = min(20, max(1, int(remaining)))
        out.extend(_drain_json_messages(ctx, queue_url, wait_s=wait_s))
    return out


def _make_lambda_zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp2-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv()
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-cp2-lpolicy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp2-prole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv()
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if statements:
        policy_name = ctx.unique_name("sim2real-cp2-ppolicy-")
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
                Tags=_resource_tags(),
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
    raise AssertionError(
        f"pipe {name} did not reach a terminal state {terminal_states} within {timeout_s}s "
        f"(last state={state!r}, reason={reason!r})"
    )


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
        "--tags", _resource_tags_cli(),
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
