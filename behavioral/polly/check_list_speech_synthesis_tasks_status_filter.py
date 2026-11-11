"""list-speech-synthesis-tasks-status-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-speech-synthesis-tasks-status-filter"
GROUP = "async-task"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once a task reaches TaskStatus=completed, ListSpeechSynthesisTasks(Status="completed")
    includes it while ListSpeechSynthesisTasks(Status="scheduled") no longer does."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)

    task_id = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="Listing filter check for Amazon Polly speech synthesis tasks.",
        VoiceId="Joanna",
    )["SynthesisTask"]["TaskId"]

    final = _poll_until(
        lambda: polly.get_speech_synthesis_task(TaskId=task_id)["SynthesisTask"],
        lambda t: t["TaskStatus"] in ("completed", "failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["TaskStatus"] == "completed", final.get("TaskStatusReason")

    completed_ids = _list_task_ids(polly, status="completed")
    assert task_id in completed_ids, completed_ids

    scheduled_ids = _list_task_ids(polly, status="scheduled")
    assert task_id not in scheduled_ids, scheduled_ids


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _list_task_ids(polly, status: str) -> set:
    ids = set()
    token = None
    while True:
        kwargs = {"Status": status}
        if token:
            kwargs["NextToken"] = token
        resp = polly.list_speech_synthesis_tasks(**kwargs)
        ids.update(t["TaskId"] for t in resp.get("SynthesisTasks", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


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
