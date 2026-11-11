"""batch-get-job-partial-failure."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-get-job-partial-failure"
GROUP = "data-plane"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetJob returns the resolvable job in `jobs` and a per-item ResourceNotFoundException
    entry in `errors` for an identifier that does not exist, in the same call."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id, displayName=ctx.unique_name("sim2real-queue-"), tags={"sim2real": CHECK}
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    job_id = deadline.create_job(
        farmId=farm_id,
        queueId=queue_id,
        template=_minimal_job_template(),
        templateType="JSON",
        priority=10,
        tags={"sim2real": CHECK},
    )["jobId"]
    ctx.on_cleanup(lambda: _safe(lambda: _archive_job(deadline, farm_id, queue_id, job_id)))
    _poll_until(
        lambda: deadline.get_job(farmId=farm_id, queueId=queue_id, jobId=job_id),
        lambda j: j["lifecycleStatus"] == "CREATE_COMPLETE",
        timeout_s=60.0,
        interval_s=3.0,
    )

    bogus_job_id = "job-" + "0" * 32
    resp = deadline.batch_get_job(
        identifiers=[
            {"farmId": farm_id, "queueId": queue_id, "jobId": job_id},
            {"farmId": farm_id, "queueId": queue_id, "jobId": bogus_job_id},
        ]
    )

    assert [j["jobId"] for j in resp["jobs"]] == [job_id], resp["jobs"]
    assert len(resp["errors"]) == 1, resp["errors"]
    error = resp["errors"][0]
    assert error["jobId"] == bogus_job_id, f"expected error entry for {bogus_job_id}, got {error['jobId']}"
    assert error["code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error['code']}"


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline, tags=None):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            kwargs = {"displayName": ctx.unique_name("sim2real-farm-")}
            if tags:
                kwargs["tags"] = tags
            return deadline.create_farm(**kwargs)["farmId"]
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


def _archive_job(deadline, farm_id: str, queue_id: str, job_id: str, timeout_s: float = 120.0) -> None:
    """Archive the job; UpdateJob refuses (ConflictException) until the job reaches a terminal
    task run status or an in-flight update finishes, so retry exactly that refusal."""
    deadline_t = time.monotonic() + timeout_s
    while True:
        try:
            deadline.update_job(farmId=farm_id, queueId=queue_id, jobId=job_id, lifecycleStatus="ARCHIVED")
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline_t:
                raise
        time.sleep(2)


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
