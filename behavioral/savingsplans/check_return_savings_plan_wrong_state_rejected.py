"""return-savings-plan-wrong-state-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "return-savings-plan-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["savingsplans"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReturnSavingsPlan on a queued plan is refused with ValidationException "Savings Plans in queued state cannot be
    returned." and leaves the plan queued; DeleteQueuedSavingsPlan on the same plan then moves it to queued-deleted.
    """
    sp = ctx.client("savingsplans")
    plan_id = _create_queued_plan(ctx, commitment="0.001")
    state = _poll_for_state(ctx, plan_id, {"queued"})
    assert state == "queued", f"expected 'queued', got {state!r}"

    err = _error(lambda: sp.return_savings_plan(savingsPlanId=plan_id))
    assert err["Code"] == "ValidationException", f"expected 'ValidationException', got {err!r}"
    assert err["Message"] == "Savings Plans in queued state cannot be returned.", f"unexpected return_queued message: {err['Message']!r}"

    unchanged_state = sp.describe_savings_plans(savingsPlanIds=[plan_id])["savingsPlans"][0]["state"]
    assert unchanged_state == "queued", f"a rejected ReturnSavingsPlan call must not change plan state, got {unchanged_state!r}"

    # Positive control: the queued plan can still be deleted legitimately.
    sp.delete_queued_savings_plan(savingsPlanId=plan_id)
    final_state = _poll_for_state(ctx, plan_id, {"queued-deleted"})
    assert final_state == "queued-deleted", f"expected 'queued-deleted', got {final_state!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _create_queued_plan(ctx, commitment: str = "0.001", client_token: str | None = None) -> str:
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    kwargs = {
        "savingsPlanOfferingId": offering_id,
        "commitment": commitment,
        "purchaseTime": _future_purchase_time(),
        "tags": {"sim2real-env": "behavioral-check"},
    }
    if client_token:
        kwargs["clientToken"] = client_token
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


def _poll_for_state(ctx, plan_id: str, expected_states: set[str], timeout_s: float = 60.0, interval_s: float = 3.0):
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
    return last_state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
