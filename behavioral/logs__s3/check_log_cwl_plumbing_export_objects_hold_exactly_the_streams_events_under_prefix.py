"""log-cwl-plumbing-export-objects-hold-exactly-the-streams-events-under-prefix."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-export-objects-hold-exactly-the-streams-events-under-prefix"
GROUP = "export"
SERVICES = ["logs", "s3"]

_TERMINAL = {"COMPLETED", "CANCELLED", "FAILED"}


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "resource:account-singleton:logs-export-task",
)
def run(ctx) -> None:
    """A stream-scoped CreateExportTask writes gzip objects at <prefix>/<taskId>/<stream>/... whose
    lines are exactly that stream's events as "<ISO-8601 UTC ms timestamp> <message>", with
    every object under the requested prefix and nothing from the sibling stream.
    """
    deadline = time.monotonic() + _CLASS_BUDGET_S - _TEARDOWN_RESERVE_S
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    account = ctx.account

    bucket = _make_export_bucket(ctx, s3, account, "sim2real-cwlp-exp-")
    group = ctx.unique_name("sim2real-cwlp-exp-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(
        _tolerant(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException")
    )
    stream_in = ctx.unique_name("in-scope-")
    stream_out = ctx.unique_name("out-of-scope-")
    for s in (stream_in, stream_out):
        logs.create_log_stream(logGroupName=group, logStreamName=s)

    marker = ctx.unique_name("cwlp-exp-")
    base = _now_ms() - 60_000
    wanted = [{"timestamp": base + i * 1_000, "message": f"{marker} keep-{i}"} for i in range(3)]
    unwanted = [{"timestamp": base + 500 + i * 1_000, "message": f"{marker} drop-{i}"}
                for i in range(2)]
    _put_and_wait(logs, group, stream_in, wanted, deadline)
    _put_and_wait(logs, group, stream_out, unwanted, deadline)
    expected_lines = {_line(e) for e in wanted}
    unwanted_msgs = {e["message"] for e in unwanted}

    # An export can report COMPLETED before the service's export index has caught up with
    # events GetLogEvents already returns, writing only the permission-check object. Each
    # attempt is a fresh task and a fresh prefix, and every attempt is held to the layout and
    # scope invariants; only COMPLETENESS is retried.
    lines: set[str] = set()
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        prefix = ctx.unique_name(f"exp-{attempt}-")
        task_id = _create_export(
            logs, taskName=ctx.unique_name("sim2real-cwlp-exp-t-"), logGroupName=group,
            logStreamNamePrefix=stream_in, destination=bucket, destinationPrefix=prefix,
            timeout_s=_left(deadline), **{"from": base - 1, "to": _now_ms() + 1_000},
        )
        ctx.on_cleanup(lambda t=task_id: _cancel_quietly(logs, t))
        task = _poll_until(
            lambda: logs.describe_export_tasks(taskId=task_id)["exportTasks"][0],
            lambda t: t["status"]["code"] in _TERMINAL,
            timeout_s=_left(deadline),
            interval_s=10.0,
            description=f"export task {task_id} reaches a terminal state",
        )
        assert task["status"]["code"] == "COMPLETED", (
            f"expected export {task_id} to COMPLETE, got {task['status']!r}"
        )
        assert (task["destination"], task["destinationPrefix"], task["logGroupName"]) == (
            bucket, prefix, group
        ), f"describe_export_tasks echoed the wrong target: {task!r}"

        keys = _all_keys(s3, bucket)
        new_keys = [k for k in keys if k.startswith(f"{prefix}/")]
        stray = [k for k in keys if not k.startswith("exp-")]
        assert stray == [], f"export wrote objects outside any requested prefix: {stray!r}"
        data_keys = [k for k in new_keys if k.endswith(".gz")]
        for k in data_keys:
            assert k.startswith(f"{prefix}/{task_id}/{stream_in}/"), (
                f"expected data object under {prefix}/{task_id}/{stream_in}/, got {k!r}"
            )
        lines = set()
        for k in data_keys:
            body = gzip.decompress(s3.get_object(Bucket=bucket, Key=k)["Body"].read())
            lines |= {ln for ln in body.decode("utf-8").splitlines() if ln}
        leaked = {ln for ln in lines if any(m in ln for m in unwanted_msgs)}
        assert not leaked, f"out-of-scope stream's events were exported: {sorted(leaked)!r}"
        extra = lines - expected_lines
        assert not extra, (
            f"export {task_id} contains lines that were never written as "
            f"'<ISO ts> <message>': {sorted(extra)!r}; expected {sorted(expected_lines)!r}"
        )
        if lines == expected_lines:
            break
        time.sleep(min(30.0, _left(deadline)))  # fresh task after the index has had real time
    assert lines == expected_lines, (
        f"after {attempt} completed exports the objects held {sorted(lines)!r}, expected exactly "
        f"{sorted(expected_lines)!r}"
    )

    # Tear down in reverse dependency order and prove each resource gone. A COMPLETED export
    # task stays describable (terminal tombstone) and can no longer be cancelled.
    done = logs.describe_export_tasks(taskId=task_id)["exportTasks"]
    assert [t["status"]["code"] for t in done] == ["COMPLETED"], (
        f"export {task_id} is not a COMPLETED tombstone: {done!r}"
    )
    _refused(lambda: logs.cancel_export_task(taskId=task_id), ("InvalidOperationException",), 400,
             f"CancelExportTask on completed {task_id}", "The specified export task has already finished")
    _gone_log_group(ctx, group)
    _gone_bucket(ctx, bucket)


#: The export-task budget (an export can take up to 600 s to reach COMPLETED) and the share of
#: it the in-body teardown keeps; every wait before it polls within the rest.
_CLASS_BUDGET_S = 600.0
_TEARDOWN_RESERVE_S = 60.0


def _left(deadline: float) -> float:
    """Seconds left before the shared deadline (at least one poll)."""
    return max(1.0, deadline - time.monotonic())


def _now_ms() -> int:
    return int(time.time() * 1000)


def _line(event: dict) -> str:
    ts = datetime.fromtimestamp(event["timestamp"] / 1000, tz=timezone.utc)
    return f"{ts.strftime('%Y-%m-%dT%H:%M:%S.')}{ts.microsecond // 1000:03d}Z {event['message']}"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _put_and_wait(logs, group: str, stream: str, events: list[dict], deadline: float) -> None:
    resp = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    assert not resp.get("rejectedLogEventsInfo"), (
        f"expected every event accepted, got {resp.get('rejectedLogEventsInfo')!r}"
    )
    want = sorted(e["message"] for e in events)
    _poll_until(
        lambda: sorted(
            e["message"]
            for e in logs.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True
            )["events"]
        ),
        lambda got: got == want,
        timeout_s=_left(deadline),
        interval_s=3.0,
        description=f"{len(want)} events readable from {stream} before export",
    )


def _create_export(logs, timeout_s: float, **kwargs) -> str:
    """Only one export task per ACCOUNT may be active, so another export in the account makes
    ours wait. Retry the create on that one code, bounded."""

    def _attempt():
        try:
            return logs.create_export_task(**kwargs)["taskId"]
        except logs.exceptions.LimitExceededException:
            return None

    return _poll_until(
        _attempt,
        lambda t: t is not None,
        timeout_s=timeout_s,
        interval_s=10.0,
        description="CreateExportTask accepted once no other export is active in the account",
    )


def _cancel_quietly(logs, task_id: str) -> None:
    status = logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"]
    if status not in _TERMINAL:
        logs.cancel_export_task(taskId=task_id)


def _all_keys(s3, bucket: str) -> list[str]:
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _make_export_bucket(ctx, s3, account: str, prefix: str) -> str:
    bucket = ctx.unique_name(prefix)
    if ctx.region == "us-east-1":  # region-pinned rule: us-east-1 takes no LocationConstraint
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(_tolerant(lambda: _empty_and_delete_bucket(s3, bucket), "NoSuchBucket"))
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


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0
_LOG_GROUP_NF = "The specified log group does not exist."


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, with exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message: str, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_log_group(ctx, name: str) -> None:
    logs = ctx.client("logs")
    logs.delete_log_group(logGroupName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: logs.describe_log_streams(logGroupName=name), nf, 400, f"DescribeLogStreams {name}", _LOG_GROUP_NF)
    listed = {g["logGroupName"] for g in logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])}
    assert name not in listed, f"DescribeLogGroups still lists deleted log group {name}"
    _refused(
        lambda: logs.put_log_events(logGroupName=name, logStreamName="gone",
                                    logEvents=[{"timestamp": int(time.time() * 1000), "message": "gone"}]),
        nf, 400, f"PutLogEvents {name}", _LOG_GROUP_NF,
    )


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", "Not Found")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}", "The specified bucket does not exist")


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", "Not Found")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}", "The specified bucket does not exist")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
