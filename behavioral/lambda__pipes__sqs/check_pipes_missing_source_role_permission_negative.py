"""pipes-missing-source-role-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipes-missing-source-role-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]

_FORWARD_CODE = """
import json
import os
import time

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]


def handler(event, context):
    bodies = [record.get("body") for record in event]
    _sqs.send_message(
        QueueUrl=_RESULTS_URL,
        MessageBody=json.dumps({"bodies": bodies, "count": len(event), "ts": time.time()}),
    )
    return {"batchItemFailures": []}
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A Pipe whose role cannot read the source queue self-disables with a StateReason and never
    consumes or delivers its message, while a correctly permitted sibling Pipe delivers normally."""
    # --- broken: pipe role has lambda:InvokeFunction but NO permission on the source queue ---
    source = _create_queue(ctx, "sim2real-pp-nsrc-")
    results = _create_queue(ctx, "sim2real-pp-nres-")
    lambda_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-pp-nfn-"), lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results["url"]}
    )
    broken_role = _create_pipe_role(
        ctx,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
    )
    broken_name = ctx.unique_name("sim2real-pp-npipe-")
    ctx.on_cleanup(lambda: _delete_pipe_and_wait(ctx, broken_name))
    ctx.client("pipes").create_pipe(
        Name=broken_name,
        RoleArn=broken_role,
        Source=source["arn"],
        Target=fn_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Tags=_resource_tags(),
    )

    body = f"blocked-{broken_name}"
    sqs = ctx.client("sqs")
    sqs.send_message(QueueUrl=source["url"], MessageBody=body)

    # the pipe is expected to self-disable because it cannot perform Queue operations
    state, reason = _poll_pipe_state(ctx, broken_name, {"STOPPED", "START_FAILED", "CREATE_FAILED"}, timeout_s=120, interval_s=5)
    assert state in ("STOPPED", "START_FAILED", "CREATE_FAILED"), (
        f"expected the pipe to self-disable due to missing source permissions, got state={state!r} reason={reason!r}"
    )
    missing_actions = ("ReceiveMessage", "DeleteMessage", "GetQueueAttributes")
    denial_markers = (
        "AccessDenied",
        "not authorized",
        "AccessDeniedException",
        "InsufficientPermissions",
        "does not have permission",
    )
    assert any(a in reason for a in missing_actions) or any(m in reason for m in denial_markers), (
        f"expected StateReason to indicate a permissions failure against the source queue, got: {reason!r}"
    )

    # effect must be absent: nothing was ever delivered, and the source message was never consumed
    leftover = _drain_json_messages(ctx, results["url"])
    assert not any(body in m.get("bodies", []) for m in leftover), "message must never reach the target"
    attrs = sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] != "0", "source message must remain unconsumed on the queue"
    reread = sqs.receive_message(QueueUrl=source["url"], MaxNumberOfMessages=1, WaitTimeSeconds=2)
    assert reread.get("Messages") and reread["Messages"][0]["Body"] == body, "the original message must still be retrievable"

    # --- positive control: identical setup, but the role has the required source permissions ---
    ctrl_source = _create_queue(ctx, "sim2real-pp-csrc-")
    ctrl_results = _create_queue(ctx, "sim2real-pp-cres-")
    ctrl_lambda_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": ctrl_results["arn"]}]
    )
    ctrl_fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-pp-cfn-"), ctrl_lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": ctrl_results["url"]}
    )
    ctrl_role = _create_pipe_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": ctrl_source["arn"],
            },
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": ctrl_fn_arn},
        ],
    )
    ctrl_name = ctx.unique_name("sim2real-pp-cpipe-")
    _create_pipe_running(
        ctx,
        ctrl_name,
        RoleArn=ctrl_role,
        Source=ctrl_source["arn"],
        Target=ctrl_fn_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Tags=_resource_tags(),
    )
    ctrl_body = f"ok-{ctrl_name}"
    sqs.send_message(QueueUrl=ctrl_source["url"], MessageBody=ctrl_body)
    delivered = _poll_until(
        lambda: _drain_json_messages(ctx, ctrl_results["url"]),
        lambda msgs: any(ctrl_body in m.get("bodies", []) for m in msgs),
        timeout_s=60,
        interval_s=3,
    )
    assert any(ctrl_body in m.get("bodies", []) for m in delivered), "positive control pipe failed to deliver"


# ===== helpers =====

_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-pp"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _TAG_PREFIX}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_queue(ctx, prefix, fifo=False, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    if fifo:
        name = f"{name}.fifo"
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    kwargs: dict[str, Any] = {"QueueName": name, "tags": _resource_tags()}
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv())
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv())
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
                Tags=_resource_tags(),
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
