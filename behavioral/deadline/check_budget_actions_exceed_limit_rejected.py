"""budget-actions-exceed-limit-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "budget-actions-exceed-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBudget rejects an actions list longer than the documented 10-item maximum with
    ValidationException and creates no budget, while a list within the limit succeeds."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        tags={"sim2real": CHECK},
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    now = datetime.now(timezone.utc)
    schedule = {"fixed": {"startTime": now, "endTime": now + timedelta(days=1)}}
    too_many_actions = [
        {"type": "STOP_SCHEDULING_AND_COMPLETE_TASKS", "thresholdPercentage": float(pct)}
        for pct in range(1, 12)
    ]
    rejected_name = ctx.unique_name("sim2real-budget-rejected-")

    # Break exactly one thing: an actions list of 11 entries (max is 10).
    error = _client_error(
        lambda: deadline.create_budget(
            farmId=farm_id,
            displayName=rejected_name,
            usageTrackingResource={"queueId": queue_id},
            approximateDollarLimit=10.0,
            actions=too_many_actions,
            schedule=schedule,
        )
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error}"
    expected_message = (
        '[array is too long: must have at most 10 elements but instance has 11 elements, '
        'format attribute "float" not supported]'
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: no budget with that display name was created.
    names = [b["displayName"] for b in deadline.list_budgets(farmId=farm_id)["budgets"]]
    assert rejected_name not in names, "rejected budget was created anyway"

    # Positive control: a single action (within the limit) succeeds.
    accepted_name = ctx.unique_name("sim2real-budget-accepted-")
    budget_id = deadline.create_budget(
        farmId=farm_id,
        displayName=accepted_name,
        usageTrackingResource={"queueId": queue_id},
        approximateDollarLimit=10.0,
        actions=too_many_actions[:1],
        schedule=schedule,
        tags={"sim2real": CHECK},
    )["budgetId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_budget(farmId=farm_id, budgetId=budget_id)))
    names = [b["displayName"] for b in deadline.list_budgets(farmId=farm_id)["budgets"]]
    assert accepted_name in names, f"expected accepted budget {accepted_name!r} in {names}"


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
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
