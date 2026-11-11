"""limit-delete-blocked-by-association-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "limit-delete-blocked-by-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLimit is rejected with ConflictException while the limit is still associated
    with a queue; the limit is left intact, and it deletes cleanly once disassociated."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(farmId=farm_id, displayName=ctx.unique_name("sim2real-queue-"))[
        "queueId"
    ]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    limit_id = deadline.create_limit(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-limit-"),
        amountRequirementName="amount.Sim2realLimitTest",
        maxCount=3,
    )["limitId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_limit(farmId=farm_id, limitId=limit_id)))

    deadline.create_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)

    # Break exactly one thing: try to delete a limit that is still associated with a queue.
    error = _client_error(lambda: deadline.delete_limit(farmId=farm_id, limitId=limit_id))
    assert error.get("Code") == "ConflictException", f"expected ConflictException, got {error}"
    assert error.get("Message") == "Request could not be completed: Limit is associated with one or more Queues.", (
        f"expected the exact ConflictException message, got {error.get('Message')!r}"
    )

    # Effect absent: the limit is still there.
    limit = deadline.get_limit(farmId=farm_id, limitId=limit_id)
    assert limit["limitId"] == limit_id, f"expected limit {limit_id} to survive, got {limit!r}"

    # Positive control: stop and delete the association, then the limit deletes cleanly.
    deadline.update_queue_limit_association(
        farmId=farm_id, queueId=queue_id, limitId=limit_id, status="STOP_LIMIT_USAGE_AND_CANCEL_TASKS"
    )
    _poll_until(
        lambda: deadline.get_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id),
        lambda a: a["status"] == "STOPPED",
        timeout_s=120.0,
        interval_s=5.0,
    )
    deadline.delete_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)
    deadline.delete_limit(farmId=farm_id, limitId=limit_id)
    final_error = _client_error(lambda: deadline.get_limit(farmId=farm_id, limitId=limit_id))
    assert final_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_error}"
    assert final_error.get("Message") == f"Resource of type limit with id {limit_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {final_error.get('Message')!r}"
    )


# ===== helpers =====
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
    """Teardown: done on ResourceNotFoundException; retries ConflictException (a child still
    being released) every 2 s for up to 60 s; raises everything else."""
    from botocore.exceptions import ClientError

    deadline_t = time.monotonic() + 60.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline_t:
                raise
        time.sleep(2)


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline_t = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline_t:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
