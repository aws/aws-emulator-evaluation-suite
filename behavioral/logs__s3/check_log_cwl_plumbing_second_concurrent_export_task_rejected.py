"""log-cwl-plumbing-second-concurrent-export-task-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-second-concurrent-export-task-rejected"
GROUP = "export"
SERVICES = ["logs", "s3"]

_TERMINAL = {"COMPLETED", "CANCELLED", "FAILED"}
_ATTEMPTS = 10


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "resource:account-singleton:logs-export-task",
)
def run(ctx) -> None:
    """While one export task is active, a second CreateExportTask to another prefix is refused with
    LimitExceededException and writes nothing; once the first COMPLETES, the same call is accepted
    and writes under its prefix.
    """
    logs = ctx.client("logs")
    # Standard retry mode classes LimitExceededException as throttling and silently retries it
    # until the first export finishes, so the refusal is only observable without retries.
    logs_once = ctx.client("logs", config=Config(retries={"max_attempts": 1}))
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _make_export_bucket(ctx, s3, account, "sim2real-cwlp-exc-")
    group = ctx.unique_name("sim2real-cwlp-exc-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = ctx.unique_name("s-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    base = _now_ms() - 60_000
    _put_and_wait(ctx, logs, group, stream, [{"timestamp": base, "message": f"{group} one line"}])

    window = {"from": base - 1, "to": _now_ms() + 1_000}
    # A one-line export can finish within a second, so the second call follows the first's
    # acceptance with no request in between. An acceptance while the first is still active
    # afterwards is the failure this check exists to catch; an acceptance once the first already
    # reached a terminal state is an inconclusive attempt: its prefix is abandoned and a fresh
    # pair is tried (bounded).
    second_prefix = ""
    first_id = first_prefix = ""
    code = message = None
    for attempt in range(1, _ATTEMPTS + 1):
        first_prefix = ctx.unique_name(f"exp-first-{attempt}-")
        second_prefix = ctx.unique_name(f"exp-second-{attempt}-")
        first_id = _create_export(
            ctx, logs, logGroupName=group, destination=bucket, destinationPrefix=first_prefix,
            **window,
        )
        ctx.on_cleanup(lambda t=first_id: _cancel_quietly(logs, t))
        try:
            wrongly = logs_once.create_export_task(
                logGroupName=group, destination=bucket, destinationPrefix=second_prefix,
                **window,
            )["taskId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            break
        ctx.on_cleanup(lambda t=wrongly: _cancel_quietly(logs, t))
        after = _status(logs, first_id)
        assert after in _TERMINAL, (
            f"expected a second export to be refused while {first_id} is {after}, but it was "
            f"accepted as {wrongly}"
        )
        _await_terminal(ctx, logs, wrongly)
        _await_terminal(ctx, logs, first_id)
    assert code is not None, (
        f"never caught the first export while still active in {_ATTEMPTS} attempts"
    )
    assert code == "LimitExceededException", (
        f"expected LimitExceededException for a concurrent export, got {code!r} ({message!r})"
    )
    assert message == "Resource limit exceeded.", (
        f"expected the concurrent-export refusal message 'Resource limit exceeded.', got {message!r}"
    )
    second_args = dict(
        logGroupName=group, destination=bucket, destinationPrefix=second_prefix, **window
    )

    first = _poll_until(
        ctx,
        lambda: logs.describe_export_tasks(taskId=first_id)["exportTasks"][0],
        lambda t: t["status"]["code"] in _TERMINAL,
        timeout_s=600.0,
        interval_s=1.0,
        description=f"the first export {first_id} reaches a terminal state",
    )
    assert first["status"]["code"] == "COMPLETED", f"first export ended {first['status']!r}"

    # --- 2. Effect absent: no task was recorded for the refused call, and its prefix is empty.
    refused = [
        t for t in _tasks_for_group(logs, group) if t.get("destinationPrefix") == second_prefix
    ]
    assert refused == [], f"the refused export was recorded as a task anyway: {refused!r}"
    keys = _all_keys(s3, bucket)
    assert [k for k in keys if k.startswith(f"{second_prefix}/")] == [], (
        f"the refused export wrote under {second_prefix}/: {keys!r}"
    )
    assert any(k.startswith(f"{first_prefix}/") for k in keys), (
        f"positive control: the accepted export wrote nothing under {first_prefix}/: {keys!r}"
    )

    # --- 3. Repair: with no active task, the identical call is accepted and writes.
    second_id = _create_export(ctx, logs, **second_args)
    ctx.on_cleanup(lambda: _cancel_quietly(logs, second_id))
    second = _poll_until(
        ctx,
        lambda: logs.describe_export_tasks(taskId=second_id)["exportTasks"][0],
        lambda t: t["status"]["code"] in _TERMINAL,
        timeout_s=600.0,
        interval_s=1.0,
        description=f"the second export {second_id} reaches a terminal state",
    )
    assert second["status"]["code"] == "COMPLETED", f"second export ended {second['status']!r}"
    assert second["destinationPrefix"] == second_prefix, f"prefix echo was {second!r}"
    later = _all_keys(s3, bucket)
    assert any(k.startswith(f"{second_prefix}/") for k in later), (
        f"the accepted second export wrote nothing under {second_prefix}/: {later!r}"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _put_and_wait(ctx, logs, group: str, stream: str, events: list[dict]) -> None:
    resp = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    assert not resp.get("rejectedLogEventsInfo"), (
        f"expected every event accepted, got {resp.get('rejectedLogEventsInfo')!r}"
    )
    want = sorted(e["message"] for e in events)
    _poll_until(
        ctx,
        lambda: sorted(
            e["message"]
            for e in logs.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True
            )["events"]
        ),
        lambda got: got == want,
        timeout_s=120.0,
        interval_s=1.0,
        description=f"{len(want)} events readable from {stream} before export",
    )


def _create_export(ctx, logs, **kwargs) -> str:
    """Only one export task per ACCOUNT may be active, so another export in the account makes
    ours wait. Retry the create on that one code, bounded."""

    def _attempt():
        try:
            return logs.create_export_task(**kwargs)["taskId"]
        except logs.exceptions.LimitExceededException:
            return None

    return _poll_until(
        ctx,
        _attempt,
        lambda t: t is not None,
        timeout_s=300.0,
        interval_s=2.0,
        description="CreateExportTask accepted once no other export is active in the account",
    )


def _cancel_quietly(logs, task_id: str) -> None:
    status = logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"]
    if status not in _TERMINAL:
        logs.cancel_export_task(taskId=task_id)


def _status(logs, task_id: str) -> str:
    return logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"]


def _await_terminal(ctx, logs, task_id: str) -> str:
    return _poll_until(
        ctx,
        lambda: _status(logs, task_id),
        lambda c: c in _TERMINAL,
        timeout_s=600.0,
        interval_s=1.0,
        description=f"export {task_id} reaches a terminal state",
    )


def _tasks_for_group(logs, group: str) -> list[dict]:
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        page = logs.describe_export_tasks(**kwargs)
        out.extend(t for t in page.get("exportTasks", []) if t.get("logGroupName") == group)
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _all_keys(s3, bucket: str) -> list[str]:
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _make_export_bucket(ctx, s3, account: str, prefix: str) -> str:
    bucket = ctx.unique_name(prefix)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    principal = {"Service": f"logs.{ctx.region}.amazonaws.com"}
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                        "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                    },
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control",
                                "aws:SourceAccount": account,
                            }
                        },
                    },
                ],
            }
        ),
    )
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
