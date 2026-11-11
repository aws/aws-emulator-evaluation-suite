"""concurrent-start-stop-race-resolves-deterministically."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-stop-race-resolves-deterministically"
GROUP = "concurrency"
SERVICES = ["pipes"]

_CONFLICT_MESSAGE = "Pipe {name} is updating concurrently."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent StartPipe and StopPipe on a RUNNING pipe: a refused call gets only ConflictException
    with its exact message, and the pipe settles STOPPED when only StopPipe succeeded, RUNNING when
    only StartPipe did, and in one of the two when both did."""
    pipes = ctx.client("pipes")
    role_arn = _create_pipes_role(ctx)
    source_url, source_arn = _create_queue(ctx, "src")
    target_url, target_arn = _create_queue(ctx, "tgt")
    _grant_pipe_permissions(ctx, role_arn, source_arn, target_arn)

    name = ctx.unique_name("sim2real-pipes-race-")
    _create_pipe_with_retry(
        ctx,
        pipes,
        Name=name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="RUNNING",
        Tags={"sim2real:managed": "true", "sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_pipe_safely(pipes, name))

    _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] == "RUNNING",
        timeout_s=180.0,
    )

    results: dict[str, Any] = {}

    def _do_start():
        try:
            pipes.start_pipe(Name=name)
            results["start"] = ("ok", None)
        except ClientError as e:
            results["start"] = ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    def _do_stop():
        try:
            pipes.stop_pipe(Name=name)
            results["stop"] = ("ok", None)
        except ClientError as e:
            results["stop"] = ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_do_start)
        f2 = pool.submit(_do_stop)
        f1.result()
        f2.result()

    outcomes = [results["start"], results["stop"]]
    successes = {k for k, v in results.items() if v[0] == "ok"}
    errors = [v[1] for v in results.values() if v[0] == "error"]
    assert successes, f"expected at least one of StartPipe/StopPipe to succeed, got {outcomes!r}"
    # Overlapping calls conflict; serialized ones may both succeed (StartPipe on RUNNING is a no-op).
    for code, message in errors:
        assert code == "ConflictException" and message == _conflict_message(name), (
            f"a refused call must get ConflictException with its exact message, got {errors!r}"
        )

    settled_states = {"start": {"RUNNING"}, "stop": {"STOPPED"}}
    allowed = set().union(*(settled_states[k] for k in successes))
    # DesiredState records the last accepted call; wait for CurrentState to settle on it.
    final = _poll_until(
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d["CurrentState"] == d["DesiredState"] or d["CurrentState"] in ("START_FAILED", "STOP_FAILED"),
        timeout_s=180.0,
    )
    assert final["CurrentState"] in allowed, (
        f"successful calls {sorted(successes)} allow a final state in {sorted(allowed)}, "
        f"got {final['CurrentState']!r}"
    )


def _conflict_message(name: str) -> str:
    return _CONFLICT_MESSAGE.format(name=name)


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_queue(ctx, suffix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-pipes-{suffix}-"),
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipes_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _grant_pipe_permissions(ctx, role_arn: str, source_arn: str, target_arn: str) -> None:
    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))


def _create_pipe_with_retry(ctx, pipes, **kwargs: Any):
    """CreatePipe, retrying for up to 60 s while the fresh execution role is still propagating."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 10.0)))
    while True:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "NotFoundException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _delete_pipe_safely(pipes, name: str) -> None:
    """DeletePipe, retrying ConflictException (pipe still transitioning) for up to 120 s."""
    deadline = time.monotonic() + 120
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
