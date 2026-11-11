"""create-job-target-task-run-status-suspended."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-job-target-task-run-status-suspended"
GROUP = "data-plane"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A job created with targetTaskRunStatus=SUSPENDED records exactly that status once
    creation completes (it does not silently default back to READY)."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(farmId=farm_id, displayName=ctx.unique_name("sim2real-queue-"))[
        "queueId"
    ]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    job_id = deadline.create_job(
        farmId=farm_id,
        queueId=queue_id,
        template=_minimal_job_template(),
        templateType="JSON",
        priority=10,
        targetTaskRunStatus="SUSPENDED",
    )["jobId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: deadline.update_job(farmId=farm_id, queueId=queue_id, jobId=job_id, lifecycleStatus="ARCHIVED")
        )
    )

    job = _poll_until(
        lambda: deadline.get_job(farmId=farm_id, queueId=queue_id, jobId=job_id),
        lambda j: j["lifecycleStatus"] == "CREATE_COMPLETE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    # Real GetJob only surfaces targetTaskRunStatus while lifecycleStatus is
    # CREATE_IN_PROGRESS (it is the goal the creation is converging to); once
    # CREATE_COMPLETE, the field is absent and taskRunStatus carries the settled
    # state, so that is the durable signal that the request was honored.
    assert job["taskRunStatus"] == "SUSPENDED", (
        f"expected taskRunStatus SUSPENDED once job creation completed, "
        f"got {job['taskRunStatus']!r} (targetTaskRunStatus={job.get('targetTaskRunStatus')!r})"
    )


def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(displayName=ctx.unique_name("sim2real-farm-"))["farmId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline_t = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline_t:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _minimal_job_template() -> str:
    return json.dumps(
        {
            "specificationVersion": "jobtemplate-2023-09",
            "name": "SimpleJob",
            "steps": [
                {
                    "name": "Step1",
                    "script": {"actions": {"onRun": {"command": "/bin/echo", "args": ["hello"]}}},
                }
            ],
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
