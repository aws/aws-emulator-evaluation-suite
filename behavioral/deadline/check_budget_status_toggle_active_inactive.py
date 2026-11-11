"""budget-status-toggle-active-inactive."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "budget-status-toggle-active-inactive"
GROUP = "state-machine"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A budget is created ACTIVE and UpdateBudget moves it to INACTIVE, but UpdateBudget(status=ACTIVE) then
    fails with ValidationException "Reactivating of INACTIVE budget is not allowed" and it stays INACTIVE."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    now = datetime.now(timezone.utc)
    budget_id = deadline.create_budget(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-budget-"),
        usageTrackingResource={"queueId": queue_id},
        approximateDollarLimit=10.0,
        actions=[{"type": "STOP_SCHEDULING_AND_COMPLETE_TASKS", "thresholdPercentage": 80.0}],
        schedule={"fixed": {"startTime": now, "endTime": now + timedelta(days=90)}},
    )["budgetId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_budget(farmId=farm_id, budgetId=budget_id)))

    budget = deadline.get_budget(farmId=farm_id, budgetId=budget_id)
    assert budget["status"] == "ACTIVE", f"expected ACTIVE at creation, got {budget['status']}"

    deadline.update_budget(farmId=farm_id, budgetId=budget_id, status="INACTIVE")
    budget = deadline.get_budget(farmId=farm_id, budgetId=budget_id)
    assert budget["status"] == "INACTIVE", f"expected INACTIVE after update, got {budget['status']}"

    # Reactivation is refused: real AWS treats INACTIVE as terminal for this budget, not a toggle.
    error = _client_error(
        lambda: deadline.update_budget(farmId=farm_id, budgetId=budget_id, status="ACTIVE")
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error}"
    expected_message = "Reactivating of INACTIVE budget is not allowed"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the refused call left the budget's status unchanged.
    budget = deadline.get_budget(farmId=farm_id, budgetId=budget_id)
    assert budget["status"] == "INACTIVE", (
        f"refused reactivation must not change status, got {budget['status']}"
    )


def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
                displayName=ctx.unique_name("sim2real-farm-"),
                tags={"sim2real:managed": "true", "sim2real": CHECK},
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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

