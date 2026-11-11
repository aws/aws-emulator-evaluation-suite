"""pipes-sqs-fifo-source-lambda-target-ordering-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-sqs-fifo-source-lambda-target-ordering-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "pipes", "sqs"]

_FORWARD_CODE = """
import json
import os
import uuid

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]


def handler(event, context):
    bodies = [record.get("body") for record in event]
    _sqs.send_message(
        QueueUrl=_RESULTS_URL,
        MessageBody=json.dumps({"bodies": bodies, "count": len(event)}),
        MessageGroupId="results",
        MessageDeduplicationId=str(uuid.uuid4()),
    )
    return {"batchItemFailures": []}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """FIFO SQS source messages within one message group arrive at the Lambda target in send order."""
    source = _create_queue(ctx, "sim2real-pp-fsrc-", fifo=True)
    # FIFO with a single group so the harness's own receive order matches send order
    # exactly, rather than relying on a wall-clock timestamp the forwarder reports.
    results = _create_queue(ctx, "sim2real-pp-fres-", fifo=True)

    lambda_role = _create_lambda_role(
        ctx,
        extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}],
    )
    fn_arn = _create_lambda_function(
        ctx,
        ctx.unique_name("sim2real-pp-ffn-"),
        lambda_role,
        _FORWARD_CODE,
        env={"RESULTS_QUEUE_URL": results["url"]},
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
    pipe_name = ctx.unique_name("sim2real-pp-fpipe-")
    _create_pipe_running(
        ctx,
        pipe_name,
        RoleArn=pipe_role,
        Source=source["arn"],
        Target=fn_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 10}},
        Tags={"sim2real": CHECK},
    )

    tag = pipe_name
    group_id = "order-group"
    expected = [f"{tag}-{i}" for i in range(3)]
    sqs = ctx.client("sqs")
    for i, body in enumerate(expected):
        sqs.send_message(QueueUrl=source["url"], MessageBody=body, MessageGroupId=group_id, MessageDeduplicationId=f"{tag}-dedup-{i}")

    def collect_ours():
        msgs = _drain_json_messages(ctx, results["url"])
        return [m for m in msgs if any(b.startswith(tag) for b in m.get("bodies", []))]

    collected: list[dict] = []

    def probe():
        collected.extend(collect_ours())
        total = sum(len(m.get("bodies", [])) for m in collected)
        return total

    _poll_until(probe, lambda total: total >= 3, timeout_s=60, interval_s=3)

    ordered_bodies: list[str] = []
    for m in collected:
        ordered_bodies.extend(m["bodies"])

    assert ordered_bodies == expected, f"expected FIFO group order {expected}, got {ordered_bodies}"


# ===== helpers =====


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_queue(ctx, prefix, fifo=False, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    if fifo:
        name = f"{name}.fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    kwargs: dict[str, Any] = {"QueueName": name, "tags": {"sim2real": CHECK}}
    if attrs:
        kwargs["Attributes"] = attrs
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
    role_name = ctx.unique_name("sim2real-pp-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-pp-lpolicy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pp-prole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if statements:
        policy_name = ctx.unique_name("sim2real-pp-ppolicy-")
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
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(2)
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


def _create_pipe_running(ctx, name, timeout_s=150, **create_kwargs):
    pipes = ctx.client("pipes")
    ctx.on_cleanup(lambda: _delete_pipe_and_wait(ctx, name))
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        attempt += 1
        pipes.create_pipe(Name=name, **create_kwargs)
        state, reason = _poll_pipe_state(ctx, name, {"RUNNING", "CREATE_FAILED", "START_FAILED"}, timeout_s=90)
        if state == "RUNNING":
            return
        _delete_pipe_and_wait(ctx, name)
        if time.monotonic() > deadline or attempt >= 3:
            raise AssertionError(f"pipe {name} never reached RUNNING (state={state}, reason={reason})")
        time.sleep(2)


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
