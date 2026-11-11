"""budget-dollar-limit-below-minimum-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "budget-dollar-limit-below-minimum-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]

_MSG_BELOW_MIN = (
    '[numeric instance is lower than the required minimum (minimum: 0.01, found: 0.001), '
    'format attribute "float" not supported]'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBudget with approximateDollarLimit below the 0.01 minimum fails on the service side with
    ValidationException and its exact message and creates no budget, while the same request at 0.01 succeeds."""
    deadline = ctx.client("deadline")
    unvalidated = _unvalidated_client(ctx)

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id, displayName=ctx.unique_name("sim2real-queue-"), tags={"sim2real": "true"}
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    now = datetime.now(timezone.utc)
    schedule = {"fixed": {"startTime": now, "endTime": now + timedelta(days=1)}}
    actions = [{"type": "STOP_SCHEDULING_AND_COMPLETE_TASKS", "thresholdPercentage": 50.0}]
    rejected_name = ctx.unique_name("sim2real-budget-rejected-")

    # Break exactly one thing: approximateDollarLimit below the 0.01 minimum. Use the
    # validation-disabled client so the out-of-range value reaches the service instead of being
    # rejected locally by botocore before any request is sent.
    code, message = _error(
        lambda: unvalidated.create_budget(
            farmId=farm_id,
            displayName=rejected_name,
            usageTrackingResource={"queueId": queue_id},
            approximateDollarLimit=0.001,
            actions=actions,
            schedule=schedule,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == _MSG_BELOW_MIN, f"unexpected message: {message!r}"

    # Effect absent: no budget with that display name was created.
    names = [b["displayName"] for b in deadline.list_budgets(farmId=farm_id)["budgets"]]
    assert rejected_name not in names, "rejected budget was created anyway"

    # Positive control: the same request at the documented minimum succeeds.
    accepted_name = ctx.unique_name("sim2real-budget-accepted-")
    budget_id = deadline.create_budget(
        farmId=farm_id,
        displayName=accepted_name,
        usageTrackingResource={"queueId": queue_id},
        approximateDollarLimit=0.01,
        actions=actions,
        schedule=schedule,
        tags={"sim2real": "true"},
    )["budgetId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_budget(farmId=farm_id, budgetId=budget_id)))
    names = [b["displayName"] for b in deadline.list_budgets(farmId=farm_id)["budgets"]]
    assert accepted_name in names


def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
            displayName=ctx.unique_name("sim2real-farm-"), tags={"sim2real": "true"}
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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx):
    """A deadline client on the harness's target with botocore's client-side parameter
    validation disabled, so an out-of-range approximateDollarLimit reaches the wire."""
    from botocore.config import Config

    return ctx.client("deadline", config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
