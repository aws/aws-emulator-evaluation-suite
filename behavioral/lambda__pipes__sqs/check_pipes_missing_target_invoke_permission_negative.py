"""pipes-missing-target-invoke-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipes-missing-target-invoke-permission-negative"
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


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A Pipe whose role lacks lambda:InvokeFunction never delivers: its messages stay redeliverable
    on the source queue, while a sibling Pipe with the invoke permission delivers normally."""
    visibility_timeout = 10

    # --- broken: pipe role can read the source but cannot invoke the Lambda target ---
    source = _create_queue(ctx, "sim2real-pp-tsrc-", attributes={"VisibilityTimeout": str(visibility_timeout)})
    results = _create_queue(ctx, "sim2real-pp-tres-")
    lambda_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-pp-tfn-"), lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": results["url"]}
    )
    broken_role = _create_pipe_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            }
            # deliberately no lambda:InvokeFunction grant
        ],
    )
    broken_name = ctx.unique_name("sim2real-pp-tpipe-")
    _create_pipe_running(
        ctx,
        broken_name,
        RoleArn=broken_role,
        Source=source["arn"],
        Target=fn_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
    )

    body = f"noinvoke-{broken_name}"
    sqs = ctx.client("sqs")
    sqs.send_message(QueueUrl=source["url"], MessageBody=body)

    # observe for a while: the target must never receive the message while the pipe is running
    observe_deadline = time.monotonic() + max(30, visibility_timeout * 3)
    delivered_bodies: set[str] = set()
    while time.monotonic() < observe_deadline:
        for m in _drain_json_messages(ctx, results["url"]):
            delivered_bodies.update(m.get("bodies", []))
        if delivered_bodies:
            break
        time.sleep(3)
    assert body not in delivered_bodies, (
        f"message must never reach a target the pipe cannot invoke: expected body {body!r} absent "
        f"from results queue, got delivered_bodies={delivered_bodies!r}"
    )

    # stop the pipe so it releases the message, then confirm directly (no contention with the
    # pipe's own poller) that the message is still on the source queue and was never consumed
    _delete_pipe_and_wait(ctx, broken_name)
    got_body_back = False
    redeliver_deadline = time.monotonic() + 60
    while time.monotonic() < redeliver_deadline and not got_body_back:
        resp = sqs.receive_message(
            QueueUrl=source["url"],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=10,
            VisibilityTimeout=5,
        )
        for m in resp.get("Messages", []):
            if m.get("Body") == body:
                got_body_back = True

    assert got_body_back, (
        f"source message must remain redeliverable (never silently dropped): expected body "
        f"{body!r} to reappear on {source['url']} after the pipe was stopped, got_body_back="
        f"{got_body_back!r}"
    )

    # --- positive control: identical setup, but the role also has lambda:InvokeFunction ---
    ctrl_source = _create_queue(ctx, "sim2real-pp-t2src-")
    ctrl_results = _create_queue(ctx, "sim2real-pp-t2res-")
    ctrl_lambda_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": ctrl_results["arn"]}]
    )
    ctrl_fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-pp-t2fn-"), ctrl_lambda_role, _FORWARD_CODE, env={"RESULTS_QUEUE_URL": ctrl_results["url"]}
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
    ctrl_name = ctx.unique_name("sim2real-pp-t2pipe-")
    _create_pipe_running(
        ctx,
        ctrl_name,
        RoleArn=ctrl_role,
        Source=ctrl_source["arn"],
        Target=ctrl_fn_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
    )
    ctrl_body = f"ok-{ctrl_name}"
    sqs.send_message(QueueUrl=ctrl_source["url"], MessageBody=ctrl_body)
    delivered = _poll_until(
        lambda: _drain_json_messages(ctx, ctrl_results["url"]),
        lambda msgs: any(ctrl_body in m.get("bodies", []) for m in msgs),
        timeout_s=60,
        interval_s=3,
        description=f"positive control delivery of {ctrl_body!r} to results queue",
    )
    assert any(ctrl_body in m.get("bodies", []) for m in delivered), (
        f"positive control pipe failed to deliver: expected body {ctrl_body!r} in results queue, "
        f"got delivered={delivered!r}"
    )


# ===== helpers =====

_MANAGED_TAG_KEY = "sim2real:managed"
_RESOURCE_PREFIX = "sim2real-pp-"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _RESOURCE_PREFIX.rstrip("-")}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _drain_json_messages(ctx, queue_url, max_messages=10, wait_s=2):
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv()
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv()
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
    create_kwargs.setdefault("Tags", _resource_tags())
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
