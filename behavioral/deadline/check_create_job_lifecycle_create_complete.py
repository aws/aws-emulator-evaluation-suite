"""create-job-lifecycle-create-complete."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-job-lifecycle-create-complete"
GROUP = "state-machine"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A job from a valid OpenJD template reaches CREATE_COMPLETE with priority 42, and on a queue with no fleet
    it settles to taskRunStatus NOT_COMPATIBLE with lifecycleStatus UPDATE_SUCCEEDED."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        tags={"sim2real": "behavioral"},
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    job_id = deadline.create_job(
        farmId=farm_id,
        queueId=queue_id,
        template=_minimal_job_template(),
        templateType="JSON",
        priority=42,
        tags={"sim2real": "behavioral"},
    )["jobId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: deadline.update_job(farmId=farm_id, queueId=queue_id, jobId=job_id, lifecycleStatus="ARCHIVED")
        )
    )

    job = _poll_until(
        lambda: deadline.get_job(farmId=farm_id, queueId=queue_id, jobId=job_id),
        lambda j: j["lifecycleStatus"] not in ("CREATE_IN_PROGRESS",),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert job["lifecycleStatus"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {job['lifecycleStatus']}"
    assert job["priority"] == 42, f"expected priority 42 to persist as submitted, got {job['priority']}"
    # No fleet is associated with this queue, so the task can never be scheduled. Real AWS
    # reconciles that asynchronously: wait for the SETTLED taskRunStatus rather than the
    # submitted targetTaskRunStatus, which is only visible for a transient window before the
    # reconciliation overwrites it, so the transient value cannot be observed reliably.
    _SETTLED_TASK_RUN_STATUSES = ("NOT_COMPATIBLE", "CANCELED", "FAILED", "SUCCEEDED")
    job = _poll_until(
        lambda: deadline.get_job(farmId=farm_id, queueId=queue_id, jobId=job_id),
        lambda j: j.get("taskRunStatus") in _SETTLED_TASK_RUN_STATUSES,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert job["taskRunStatus"] == "NOT_COMPATIBLE", (
        f"expected taskRunStatus NOT_COMPATIBLE (no fleet association to run on), "
        f"got {job['taskRunStatus']}"
    )
    assert job["lifecycleStatus"] == "UPDATE_SUCCEEDED", (
        f"expected lifecycleStatus UPDATE_SUCCEEDED once the no-fleet reconciliation "
        f"completes, got {job['lifecycleStatus']}"
    )


def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
                displayName=ctx.unique_name("sim2real-farm-"), tags={"sim2real": "behavioral"}
            )["farmId"]
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

