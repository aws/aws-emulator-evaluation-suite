"""e2e-pipe-filter-drops-nonmatching-events."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipe-filter-drops-nonmatching-events"
GROUP = "e2e"
SERVICES = ["pipes"]

_RESOURCE_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes-filt"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterCriteria lets a matching event through but drops a non-matching one."""
    ctx.client("pipes")
    sqs = ctx.client("sqs")

    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-filt-src-")
    target_url, target_arn = _create_queue(ctx, "sim2real-pipes-filt-dst-")
    role_arn, role_name, policy_name = _create_pipe_role(ctx, [source_arn], [target_arn])
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    pipe_name = ctx.unique_name("sim2real-pipes-filt-")
    filter_pattern = json.dumps({"body": [{"prefix": "MATCH-"}]})
    _create_pipe_with_retry(
        ctx,
        Name=pipe_name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="RUNNING",
        SourceParameters={"FilterCriteria": {"Filters": [{"Pattern": filter_pattern}]}},
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, pipe_name))

    _wait_for_pipe_state(ctx, pipe_name, {"RUNNING"})

    match_marker = uuid.uuid4().hex
    skip_marker = uuid.uuid4().hex
    sqs.send_message(QueueUrl=source_url, MessageBody=f"MATCH-{match_marker}")
    sqs.send_message(QueueUrl=source_url, MessageBody=f"SKIP-{skip_marker}")

    seen_bodies: list[str] = []
    delivered_match = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and delivered_match is None:
        resp = sqs.receive_message(QueueUrl=target_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target_url, ReceiptHandle=msg["ReceiptHandle"])
            seen_bodies.append(msg["Body"])
            if match_marker in msg["Body"]:
                delivered_match = msg["Body"]

    assert delivered_match is not None, "matching message never reached target queue"
    assert skip_marker not in delivered_match, (
        f"delivered match body unexpectedly also carried the skip marker: {delivered_match!r}"
    )

    # Extra bounded poll: the non-matching message must not turn up late either.
    extra_deadline = time.monotonic() + 30.0
    while time.monotonic() < extra_deadline:
        resp = sqs.receive_message(QueueUrl=target_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=target_url, ReceiptHandle=msg["ReceiptHandle"])
            seen_bodies.append(msg["Body"])

    assert not any(skip_marker in body for body in seen_bodies), (
        "non-matching event was delivered to target despite FilterCriteria"
    )


# ===== helpers =====


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_RESOURCE_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_delete_queue(ctx, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _safe_delete_queue(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _safe_delete_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    try:
        desc = pipes.describe_pipe(Name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    if desc["CurrentState"] not in ("STOPPED", "CREATE_FAILED", "STOP_FAILED"):
        try:
            pipes.stop_pipe(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            _wait_for_pipe_state(ctx, name, {"STOPPED", "CREATE_FAILED", "STOP_FAILED"}, timeout_s=90.0)
        except AssertionError:
            pass
    # DeletePipe can still race the STOPPING->STOPPED transition above with a ConflictException;
    # retry through it instead of giving up after one attempt and leaking the pipe.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _create_pipe_role(ctx, source_arns: list[str], target_arns: list[str]) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv())
    role_arn = role["Role"]["Arn"]
    policy_name = ctx.unique_name("sim2real-pipes-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arns,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    return role_arn, role_name, policy_name


def _create_pipe_with_retry(ctx, timeout_s: float = 60.0, **kwargs):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    assert last_exc is not None, f"create_pipe retry loop for {kwargs.get('Name')!r} exited with no exception recorded"
    raise last_exc


def _wait_for_pipe_state(ctx, name: str, target_states: set[str], timeout_s: float = 120.0, interval_s: float = 3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = pipes.describe_pipe(Name=name)
        last = resp["CurrentState"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {target_states}, last state was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
