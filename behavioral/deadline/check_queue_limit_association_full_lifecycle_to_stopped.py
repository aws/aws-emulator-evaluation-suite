"""queue-limit-association-full-lifecycle-to-stopped."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "queue-limit-association-full-lifecycle-to-stopped"
GROUP = "state-machine"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A queue-limit association starts ACTIVE, drains to STOPPED once limit usage is
    stopped, and can only be deleted once STOPPED."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        tags={"sim2real": CHECK},
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    limit_id = deadline.create_limit(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-limit-"),
        amountRequirementName="amount.Sim2realLimitTest",
        maxCount=5,
    )["limitId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_limit(farmId=farm_id, limitId=limit_id)))

    deadline.create_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)
    assoc = deadline.get_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)
    assert assoc["status"] == "ACTIVE", f"expected ACTIVE, got {assoc['status']}"

    deadline.update_queue_limit_association(
        farmId=farm_id,
        queueId=queue_id,
        limitId=limit_id,
        status="STOP_LIMIT_USAGE_AND_CANCEL_TASKS",
    )
    _poll_until(
        lambda: deadline.get_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id),
        lambda a: a["status"] == "STOPPED",
        timeout_s=120.0,
        interval_s=5.0,
    )
    # Independent re-read: STOPPED is a terminal state, not a transient one the target
    # might bounce out of on the very next read.
    settled = deadline.get_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)
    assert settled["status"] == "STOPPED", f"expected STOPPED to hold, got {settled['status']}"

    deadline.delete_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)
    error = _client_error(
        lambda: deadline.get_queue_limit_association(farmId=farm_id, queueId=queue_id, limitId=limit_id)
    )
    assert error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error}"
    assert error.get("Message") == (
        f"Resource of type queue-limit-association with id {farm_id}, {queue_id} and {limit_id} "
        "does not exist."
    ), (
        f"expected the exact ResourceNotFoundException message, got {error.get('Message')!r}"
    )

    # The delete must also make the association unusable, not merely unreadable: a mutation
    # against the dead id fails the same way an independent read does.
    mutate_error = _client_error(
        lambda: deadline.update_queue_limit_association(
            farmId=farm_id,
            queueId=queue_id,
            limitId=limit_id,
            status="STOP_LIMIT_USAGE_AND_CANCEL_TASKS",
        )
    )
    assert mutate_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {mutate_error}"
    assert mutate_error.get("Message") == (
        f"Resource of type queue-limit-association with id {farm_id}, {queue_id} and {limit_id} "
        "does not exist."
    ), (
        f"expected the exact ResourceNotFoundException message, got {mutate_error.get('Message')!r}"
    )


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
                displayName=ctx.unique_name("sim2real-farm-"), tags={"sim2real": CHECK}
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
