"""sqs-source-lambda-target-unrecognized-item-identifier-redelivers-whole-batch."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-source-lambda-target-unrecognized-item-identifier-redelivers-whole-batch"
GROUP = "event-propagation"
SERVICES = ["iam", "lambda", "logs", "pipes", "sqs"]

_VISIBILITY_S = 20
_N = 5

# Runs INSIDE the deployed function. `event` is the raw array of SQS records Pipes hands to a
# Lambda target (no "Records" wrapper). On any invocation that sees a first-attempt record, the
# handler reports one bogus itemIdentifier that names no message anywhere in the batch.
_HANDLER_CODE = """
import json
import os

import boto3

_sqs = boto3.client("sqs")
_RESULTS_URL = os.environ["RESULTS_QUEUE_URL"]


def handler(event, context):
    report = []
    any_first_attempt = False
    for record in event:
        body = json.loads(record["body"])
        rc = int(record["attributes"]["ApproximateReceiveCount"])
        report.append({"idx": body["idx"], "rc": rc})
        if rc == 1:
            any_first_attempt = True
    _sqs.send_message(QueueUrl=_RESULTS_URL, MessageBody=json.dumps({"report": report}))
    if any_first_attempt:
        return {"batchItemFailures": [{"itemIdentifier": "sim2real-not-a-real-message-id"}]}
    return {"batchItemFailures": []}
"""


# timing:real-time — visibility: 20 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A Lambda target's batchItemFailures naming an itemIdentifier that matches no message in
    the batch fails the WHOLE batch: every message is redelivered (receive count 2), not just
    the one the bogus identifier happens to resemble."""
    source = _create_queue(ctx, VisibilityTimeout=str(_VISIBILITY_S))
    results = _create_queue(ctx)

    lambda_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results["arn"]}]
    )
    fn_arn = _create_lambda_function(
        ctx, ctx.unique_name("sim2real-pbig-fn-"), lambda_role, _HANDLER_CODE,
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
    pipe_name = ctx.unique_name("sim2real-pbig-pipe-")
    _create_pipe_running(
        ctx, pipe_name, RoleArn=pipe_role, Source=source["arn"], Target=fn_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": _N}},
    )

    sqs = ctx.client("sqs")
    for idx in range(_N):
        sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"idx": idx}))

    expected = {idx: frozenset({1, 2}) for idx in range(_N)}
    tally = _collect_tally(ctx, results["url"], lambda t: t == expected, timeout_s=180)
    _wait_queue_empty(ctx, source["url"], timeout_s=90)

    assert tally == expected, (
        f"receive-count sets {dict(sorted((k, sorted(v)) for k, v in tally.items()))!r} != "
        f"expected {dict(sorted((k, sorted(v)) for k, v in expected.items()))!r}: an itemIdentifier "
        f"naming no message in the batch must redeliver every member of that batch (receive count "
        f"2 for every idx), not leave any of them deleted after a single delivery"
    )


# ===== helpers =====


def _wait_queue_empty(ctx, url, timeout_s=90.0, interval_s=2.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    last = None
    zeros = 0
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        last = attrs
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            zeros += 1
            if zeros >= 2:
                return
        else:
            zeros = 0
        time.sleep(interval_s)
    raise AssertionError(f"source queue {url} never drained to (0,0) within {timeout_s}s; last={last!r}")


def _collect_tally(ctx, results_url, predicate, timeout_s=180.0, interval_s=2.0):
    """Drain the results queue, accumulating {idx: frozenset(receive counts seen)}, until
    `predicate(tally)` holds or the budget runs out; returns the last tally either way so the
    caller's assertion reports the real, exact outcome rather than a bare timeout."""
    sqs = ctx.client("sqs")
    tally: dict[int, set[int]] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=results_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=results_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            for entry in body["report"]:
                tally.setdefault(entry["idx"], set()).add(entry["rc"])
        frozen = {idx: frozenset(v) for idx, v in tally.items()}
        if predicate(frozen):
            return frozen
        time.sleep(interval_s)
    return {idx: frozenset(v) for idx, v in tally.items()}


def _create_queue(ctx, **attrs: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pbig-q-")
    kwargs: dict[str, Any] = {"QueueName": name}
    if attrs:
        kwargs["Attributes"] = dict(attrs)
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _make_lambda_zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pbig-lrole-")
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
        policy_name = ctx.unique_name("sim2real-pbig-lpolicy-")
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pbig-prole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-pbig-ppolicy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return resp["Role"]["Arn"]


def _create_lambda_function(ctx, name, role_arn, code, env=None, timeout=15):
    lam = ctx.client("lambda")
    zip_bytes = _make_lambda_zip(code)
    deadline = time.monotonic() + 90
    last_err = None
    resp = None
    ctx.on_cleanup(lambda _n=name: _reap_log_group(ctx, f"/aws/lambda/{_n}"))
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": zip_bytes}, Timeout=timeout, Environment={"Variables": env or {}},
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


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent; a late-flushed log
    stream can recreate it after a first delete, so one delete is not a teardown."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
