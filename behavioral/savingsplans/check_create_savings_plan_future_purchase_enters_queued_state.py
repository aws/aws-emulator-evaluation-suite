"""create-savings-plan-future-purchase-enters-queued-state."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-savings-plan-future-purchase-enters-queued-state"
GROUP = "state"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSavingsPlan with a purchaseTime far in the future enters the 'queued' state (rather
    than payment-pending/active), per the documented state machine, and is described with the
    commitment/payment fields that were requested."""
    sp = ctx.client("savingsplans")
    commitment = "0.001"
    plan_id = _create_queued_plan(ctx, commitment=commitment)

    state = _poll_for_state(ctx, plan_id, {"queued", "queued-deleted", "payment-failed"})
    assert state == "queued", f"expected 'queued', got {state!r}"

    plan = sp.describe_savings_plans(savingsPlanIds=[plan_id])["savingsPlans"][0]
    assert plan["state"] == "queued", f"expected state 'queued' on the independent read, got {plan['state']!r}"
    assert plan["paymentOption"] == "No Upfront", f"expected paymentOption 'No Upfront', got {plan['paymentOption']!r}"
    assert plan["savingsPlanType"] == "Compute", f"expected savingsPlanType 'Compute', got {plan['savingsPlanType']!r}"
    # AWS echoes commitment reformatted to a fixed 8-decimal string ("0.001" -> "0.00100000"), not
    # the literal request bytes, so compare numerically.
    assert Decimal(plan["commitment"]) == Decimal(commitment), (
        f"expected commitment {commitment!r} echoed back, got {plan['commitment']!r}"
    )


def _future_purchase_time():
    return datetime.now(timezone.utc) + timedelta(days=200)


def _get_cheap_offering(ctx) -> str:
    sp = ctx.client("savingsplans")
    # Pin the search to the shortest term the offering catalog sells (`durations` is "The duration,
    # in seconds" per the savingsplans Smithy model; 31536000 = 1 year). With no term filter the
    # catalog can hand back a 3-YEAR offering, which triples the residual commitment if a queued
    # plan ever escapes cleanup: at commitment="0.001" per hour a 1-year term bounds the residual
    # at ~$8.76, versus ~$26.28 for a 3-year term.
    resp = sp.describe_savings_plans_offerings(
        planTypes=["Compute"],
        paymentOptions=["No Upfront"],
        currencies=["USD"],
        durations=[31536000],
        maxResults=1,
    )
    results = resp.get("searchResults", [])
    if not results:
        raise AssertionError("no Compute / No Upfront / USD savings plan offerings available")
    return results[0]["offeringId"]


def _safe_delete_queued(ctx, plan_id: str) -> None:
    from botocore.exceptions import ClientError

    sp = ctx.client("savingsplans")
    try:
        sp.delete_queued_savings_plan(savingsPlanId=plan_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_queued_plan(ctx, commitment: str = "0.001") -> str:
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    kwargs = {
        "savingsPlanOfferingId": offering_id,
        "commitment": commitment,
        "purchaseTime": _future_purchase_time(),
        "tags": {"sim2real-env": "behavioral-check"},
    }
    # Residual cost if cleanup does not run: the plan activates at purchaseTime and bills
    # `commitment` per hour for the full term, with no further cancel path once it is active.
    # DeleteQueuedSavingsPlan ("Deletes the queued purchase for the specified Savings Plan") is the
    # ONLY cleanup that works here, and only while the plan is still `queued` -- which is why
    # purchaseTime is 200 days out. ReturnSavingsPlan ("Returns the specified Savings Plan") has
    # only a narrow post-purchase return window and is not usable on a queued plan.
    resp = sp.create_savings_plan(**kwargs)
    plan_id = resp["savingsPlanId"]
    ctx.on_cleanup(lambda: _safe_delete_queued(ctx, plan_id))
    return plan_id


def _poll_for_state(ctx, plan_id: str, expected_states: set[str], timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    sp = ctx.client("savingsplans")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        plans = sp.describe_savings_plans(savingsPlanIds=[plan_id]).get("savingsPlans", [])
        if plans:
            last_state = plans[0]["state"]
            if last_state in expected_states:
                return last_state
        time.sleep(interval_s)
    raise AssertionError(
        f"savings plan {plan_id} did not reach one of {sorted(expected_states)} within {timeout_s}s; "
        f"last observed state={last_state!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
