"""cli-update-sqs-queue-policy-enables-eventbridge-delivery."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-update-sqs-queue-policy-enables-eventbridge-delivery"
GROUP = "cli-workflow"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule targeting an SQS queue that lacks a permissive queue policy delivers nothing;
    after `aws sqs set-queue-attributes` adds an events.amazonaws.com statement, subsequent
    matching events are delivered."""
    require_tools("aws")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    rule_name = ctx.unique_name("sim2real-policy-rule-")
    rule_arn = f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}"
    detail_type = "sim2real-policy-test"

    queue = _create_queue(ctx, "target")
    ctx.on_cleanup(lambda: _remove_targets_and_delete_rule(ctx, rule_name, ["1"]))
    _run_aws(
        ctx,
        "events",
        "put-rule",
        "--name",
        rule_name,
        "--event-pattern",
        json.dumps({"source": ["sim2real.test"], "detail-type": [detail_type]}),
    )
    _run_aws(
        ctx,
        "events",
        "put-targets",
        "--rule",
        rule_name,
        "--targets",
        json.dumps([{"Id": "1", "Arn": queue["arn"]}]),
    )

    marker_before = ctx.unique_name("before-")
    _put_event(ctx, detail_type, marker_before)
    before = _drain_queue_for(ctx, queue["url"], lambda body: _detail_marker(body) == marker_before, timeout_s=30.0)
    assert before is None, "message delivered to SQS target despite missing queue policy"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    _run_aws(
        ctx,
        "sqs",
        "set-queue-attributes",
        "--queue-url",
        queue["url"],
        "--attributes",
        json.dumps({"Policy": json.dumps(policy)}),
    )

    # Queue-policy propagation is not instantaneous; retry sending fresh events until one gets
    # through, bounded by a generous overall deadline.
    deadline = time.monotonic() + 60.0
    after = None
    while time.monotonic() < deadline and after is None:
        marker_after = ctx.unique_name("after-")
        _put_event(ctx, detail_type, marker_after)
        after = _drain_queue_for(ctx, queue["url"], lambda body: _detail_marker(body) == marker_after, timeout_s=8.0)

    assert after is not None, "message never delivered to SQS target after policy update"


def _put_event(ctx, detail_type, marker):
    _run_aws(
        ctx,
        "events",
        "put-events",
        "--entries",
        json.dumps(
            [{"Source": "sim2real.test", "DetailType": detail_type, "Detail": json.dumps({"marker": marker})}]
        ),
    )


def _detail_marker(body):
    if not isinstance(body, dict):
        return None
    detail = body.get("detail")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (json.JSONDecodeError, ValueError):
            return None
    if isinstance(detail, dict):
        return detail.get("marker")
    return None


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


def _remove_targets_and_delete_rule(ctx, rule_name, target_ids):
    events = ctx.client("events")
    try:
        events.remove_targets(Rule=rule_name, Ids=target_ids)
    except events.exceptions.ResourceNotFoundException:
        pass
    try:
        events.delete_rule(Name=rule_name)
    except events.exceptions.ResourceNotFoundException:
        pass


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
