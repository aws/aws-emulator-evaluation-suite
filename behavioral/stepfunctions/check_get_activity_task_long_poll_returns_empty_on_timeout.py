"""get-activity-task-long-poll-returns-empty-on-timeout."""
from __future__ import annotations

import time

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-activity-task-long-poll-returns-empty-on-timeout"
GROUP = "visibility-timeout-ttl"
SERVICES = ["stepfunctions"]


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetActivityTask.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """GetActivityTask against an activity with no scheduled work must long-poll (holding the
    connection for a meaningful stretch of the up-to-60s window) and then return an empty
    taskToken/input rather than erroring or returning immediately as if no poll happened."""
    # GetActivityTask long-polls server-side for up to ~60s, the same order of magnitude as
    # boto3's default 60s client read timeout, so a stock client can race the server's own
    # response with a spurious ReadTimeoutError. Pin the read timeout comfortably above the
    # server's window instead of catching the race after the fact.
    sfn = ctx.client("stepfunctions", config=Config(read_timeout=70, connect_timeout=10))
    activity_arn = _create_activity(ctx)

    started = time.monotonic()
    resp = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("idle-worker-"))
    elapsed = time.monotonic() - started

    assert resp.get("taskToken", "") == "", f"expected empty taskToken with no scheduled work, got {resp.get('taskToken')!r}"
    assert not resp.get("input"), f"expected no input alongside an empty taskToken, got {resp.get('input')!r}"
    assert elapsed >= 15.0, f"expected GetActivityTask to long-poll noticeably, only waited {elapsed:.1f}s"
    assert elapsed < 65.0, (
        f"expected GetActivityTask to return within its ~60s long-poll window, waited {elapsed:.1f}s"
    )


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    activity_name = ctx.unique_name("sim2real-behav-activity-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": "1"}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))
    return activity_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
