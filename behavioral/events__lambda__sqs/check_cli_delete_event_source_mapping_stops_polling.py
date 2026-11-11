"""cli-delete-event-source-mapping-stops-polling."""
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

CHECK = "cli-delete-event-source-mapping-stops-polling"
GROUP = "cli-workflow"
SERVICES = ["events", "lambda", "sqs"]

RELAY_HANDLER_CODE = """
import json
import os
import boto3

sqs = boto3.client("sqs")
SINK_QUEUE_URL = os.environ["SINK_QUEUE_URL"]


def handler(event, context):
    sqs.send_message(QueueUrl=SINK_QUEUE_URL, MessageBody=json.dumps(event))
    return {"status": "ok"}
"""

LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """After `aws lambda delete-event-source-mapping`, a mutation on the mapping UUID fails not-found with
    its exact message, and a later message is never relayed but stays receivable on the source queue;
    the absence window is sized from the positive control's measured delivery latency."""
    require_tools("aws")

    source = _create_queue(ctx, "src")
    sink = _create_queue(ctx, "sink")
    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source["arn"],
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]},
        ],
    )
    fn = _create_relay_lambda(ctx, role_arn, sink["url"])

    esm = _run_aws(
        ctx,
        "lambda",
        "create-event-source-mapping",
        "--function-name",
        fn["name"],
        "--event-source-arn",
        source["arn"],
        "--batch-size",
        "1",
    )
    uuid_ = esm["UUID"]
    _wait_esm_enabled(ctx, uuid_)

    marker1 = ctx.unique_name("before-")
    send1_at = time.monotonic()
    _run_aws(ctx, "sqs", "send-message", "--queue-url", source["url"], "--message-body", marker1)
    delivered = _drain_queue_for(
        ctx, sink["url"], lambda body: isinstance(body, dict) and _record_body(body) == marker1
    )
    assert delivered is not None, "event source mapping never relayed the first message (positive control failed)"
    positive_latency_s = time.monotonic() - send1_at

    _run_aws(ctx, "lambda", "delete-event-source-mapping", "--uuid", uuid_)
    _wait_esm_deleted(ctx, uuid_)

    lam = ctx.client("lambda")
    try:
        lam.update_event_source_mapping(UUID=uuid_, BatchSize=2)
    except lam.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"]["Message"]
        assert message == _ESM_GONE, f"expected {_ESM_GONE!r}, got {message!r}"
    else:
        raise AssertionError("update-event-source-mapping succeeded against a deleted mapping UUID")

    # Deletion tears down the mapping resource immediately, but a poll cycle already in
    # flight when the delete lands can still relay one more batch. Hold absence for a
    # multiple of the positive control's OWN measured delivery latency on this same wiring
    # -- never a fixed guess -- so a genuinely-stopped poller isn't hurried past a straggler
    # cycle, while continuously reconfirming the mapping stays gone throughout the window.
    hold_s = max(30.0, positive_latency_s * 3)
    _hold_while_confirming_deleted(ctx, uuid_, hold_s)

    marker2 = ctx.unique_name("after-")
    _run_aws(ctx, "sqs", "send-message", "--queue-url", source["url"], "--message-body", marker2)

    relayed_after_delete = _drain_queue_for(
        ctx, sink["url"], lambda body: isinstance(body, dict) and _record_body(body) == marker2, timeout_s=30.0
    )
    assert relayed_after_delete is None, "message was relayed even though the event source mapping was deleted"

    sqs = ctx.client("sqs")
    sink_depth = sqs.get_queue_attributes(
        QueueUrl=sink["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert sink_depth == "0", (
        f"sink queue shows {sink_depth!r} approximate message(s) after the negative window; expected 0"
    )

    resp = sqs.receive_message(QueueUrl=source["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5)
    messages = resp.get("Messages", [])
    assert messages and messages[0]["Body"] == marker2, "message did not remain on the source queue unconsumed"
    sqs.delete_message(QueueUrl=source["url"], ReceiptHandle=messages[0]["ReceiptHandle"])


def _record_body(event: dict):
    records = event.get("Records") or []
    if not records:
        return None
    return records[0].get("body")


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


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
        env_extra={"AWS_PAGER": ""},
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_queue(ctx, name_hint="q"):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{name_hint}-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_lambda_role(ctx, extra_policy_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if extra_policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _build_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_relay_lambda(ctx, role_arn, sink_queue_url):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-relay-")
    zip_bytes = _build_zip(RELAY_HANDLER_CODE)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"SINK_QUEUE_URL": sink_queue_url}},
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": fn_name, "arn": resp["FunctionArn"]}


def _wait_esm_enabled(ctx, uuid_, timeout_s=90.0, interval_s=3.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        resp = lam.get_event_source_mapping(UUID=uuid_)
        state = resp.get("State")
        if state == "Enabled":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"event source mapping never reached Enabled (last state={state})")


def _wait_esm_deleted(ctx, uuid_, timeout_s=60.0, interval_s=3.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.get_event_source_mapping(UUID=uuid_)
        except lam.exceptions.ResourceNotFoundException:
            return
        time.sleep(interval_s)
    raise AssertionError("event source mapping was not deleted in time")


#: Lambda's refusal for an event source mapping UUID that does not exist.
_ESM_GONE = "The resource you requested does not exist."


def _hold_while_confirming_deleted(ctx, uuid_, hold_s, interval_s=5.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        try:
            lam.get_event_source_mapping(UUID=uuid_)
        except lam.exceptions.ResourceNotFoundException as exc:
            message = exc.response["Error"]["Message"]
            assert message == _ESM_GONE, f"expected {_ESM_GONE!r}, got {message!r}"
        else:
            raise AssertionError(
                f"deleted event source mapping {uuid_} became visible again during the grace window"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval_s, remaining))


def _drain_queue_for(ctx, queue_url, match_fn, timeout_s=60.0, interval_s=2.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                parsed = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                parsed = msg["Body"]
            if match_fn(parsed):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return parsed
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
