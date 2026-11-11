"""cli-sqs-missing-queue-policy-put-targets-succeeds-but-no-delivery."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-sqs-missing-queue-policy-put-targets-succeeds-but-no-delivery"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"
_MANAGED_TAGS = {_MANAGED_TAG_KEY: "true"}


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws events put-targets accepts an SQS target without a queue policy (FailedEntryCount 0),
    but only the target on the same rule whose queue policy grants EventBridge receives the
    event."""
    require_tools("aws")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    rule_name = ctx.unique_name("sim2real-nopolicy-rule-")
    rule_arn = f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}"
    detail_type = "sim2real-nopolicy-test"

    no_policy_queue = _create_queue(ctx, "nopolicy")
    with_policy_queue = _create_queue(ctx, "withpolicy")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": with_policy_queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=with_policy_queue["url"], Attributes={"Policy": json.dumps(policy)}
    )

    ctx.on_cleanup(lambda: _remove_targets_and_delete_rule(ctx, rule_name, ["1", "2"]))
    _run_aws(
        ctx,
        "events",
        "put-rule",
        "--name",
        rule_name,
        "--event-pattern",
        json.dumps({"source": ["sim2real.test"], "detail-type": [detail_type]}),
        "--tags",
        json.dumps([{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]),
    )

    put_targets_result = _run_aws(
        ctx,
        "events",
        "put-targets",
        "--rule",
        rule_name,
        "--targets",
        json.dumps(
            [
                {"Id": "1", "Arn": no_policy_queue["arn"]},
                {"Id": "2", "Arn": with_policy_queue["arn"]},
            ]
        ),
    )
    assert put_targets_result.get("FailedEntryCount", -1) == 0, (
        "put-targets should succeed at the control plane even for a queue lacking a policy"
    )

    marker = ctx.unique_name("marker-")
    _run_aws(
        ctx,
        "events",
        "put-events",
        "--entries",
        json.dumps(
            [{"Source": "sim2real.test", "DetailType": detail_type, "Detail": json.dumps({"marker": marker})}]
        ),
    )

    positive_start = time.monotonic()
    delivered_with_policy = _drain_queue_for(
        ctx, with_policy_queue["url"], lambda body: _detail_marker(body) == marker, timeout_s=60.0
    )
    positive_latency_s = time.monotonic() - positive_start
    assert delivered_with_policy is not None, "positive control failed: policy-backed queue never received the event"

    # Hold the absence window past the positive control's OWN observed latency on this
    # same wiring/run, not a fixed guess -- a window shorter than the positive leg's latency
    # would score a correct-but-slower target as "blocked".
    negative_window_s = max(15.0, 3.0 * positive_latency_s)
    delivered_without_policy = _drain_queue_for(
        ctx,
        no_policy_queue["url"],
        lambda body: _detail_marker(body) == marker,
        timeout_s=negative_window_s,
    )
    assert delivered_without_policy is None, "event was delivered to a queue that lacked a permissive queue policy"


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
        QueueName=ctx.unique_name(f"sim2real-{name_hint}-"), tags=dict(_MANAGED_TAGS)
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
