"""list-speech-synthesis-tasks-ordered-by-creation-time-descending."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-speech-synthesis-tasks-ordered-by-creation-time-descending"
GROUP = "async-task"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSpeechSynthesisTasks returns tasks ordered by CreationTime descending: a task
    started (and completed) after another must appear earlier in the unfiltered listing,
    consistent with the CreationTime each task itself reports."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)

    # Task A runs to a terminal state before B starts, and B starts once the clock is past the
    # second after A's CreationTime, so the two values differ even at whole-second resolution.
    task_a = _start_and_wait(polly, bucket, "First task started for ordering check.")
    _wait_past(task_a["CreationTime"] + timedelta(seconds=1))
    task_b = _start_and_wait(polly, bucket, "Second task started for ordering check.")

    ordered_ids = _list_all_task_ids(polly)
    assert task_a["TaskId"] in ordered_ids and task_b["TaskId"] in ordered_ids, (
        f"expected both tasks in the listing, got {ordered_ids}"
    )
    pos_a = ordered_ids.index(task_a["TaskId"])
    pos_b = ordered_ids.index(task_b["TaskId"])
    assert pos_b < pos_a, (
        f"expected the more-recently-created task to list first (descending CreationTime), "
        f"got positions a={pos_a} b={pos_b} in {ordered_ids}"
    )

    # Confirm the position-based ordering against the target's own reported CreationTime
    # (the actual sort key), not the wall-clock order we happened to issue calls in.
    assert task_b["CreationTime"] > task_a["CreationTime"], (
        f"expected b's CreationTime after a's (b listed first), got b={task_b['CreationTime']} "
        f"a={task_a['CreationTime']}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-polly-tts"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _start_and_wait(polly, bucket: str, text: str) -> dict:
    started = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text=text,
        VoiceId="Joanna",
    )["SynthesisTask"]
    task = _poll_until(
        lambda: polly.get_speech_synthesis_task(TaskId=started["TaskId"])["SynthesisTask"],
        lambda t: t["TaskStatus"] in ("completed", "failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert task["TaskStatus"] == "completed", (
        f"task {started['TaskId']} did not complete: {task.get('TaskStatusReason')}"
    )
    return task


def _list_all_task_ids(polly) -> list:
    ids = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = polly.list_speech_synthesis_tasks(**kwargs)
        ids.extend(t["TaskId"] for t in resp.get("SynthesisTasks", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _wait_past(instant, timeout_s: float = 5.0) -> None:
    """Wait until the clock is past instant, for at most timeout_s."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if datetime.now(timezone.utc) > instant:
            return
        time.sleep(0.2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
