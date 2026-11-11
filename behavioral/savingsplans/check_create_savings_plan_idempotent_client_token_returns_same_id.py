"""create-savings-plan-idempotent-client-token-returns-same-id."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-savings-plan-idempotent-client-token-returns-same-id"
GROUP = "idempotency"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two CreateSavingsPlan calls with an identical clientToken and identical parameters return
    the same savingsPlanId, and only a single plan record is actually created."""
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    purchase_time = datetime.now(timezone.utc) + timedelta(days=200)
    token = str(uuid.uuid4())

    kwargs = {
        "savingsPlanOfferingId": offering_id,
        "commitment": "0.001",
        "purchaseTime": purchase_time,
        "clientToken": token,
        "tags": {"sim2real-env": "behavioral-check"},
    }

    # Residual cost if cleanup does not run: the plan activates at purchaseTime and bills
    # `commitment` per hour for the full term, with no further cancel path once it is active.
    # DeleteQueuedSavingsPlan ("Deletes the queued purchase for the specified Savings Plan") is the
    # ONLY cleanup that works here, and only while the plan is still `queued` -- which is why
    # purchaseTime is 200 days out. ReturnSavingsPlan ("Returns the specified Savings Plan") has
    # only a narrow post-purchase return window and is not usable on a queued plan.
    resp1 = sp.create_savings_plan(**kwargs)
    plan_id1 = resp1["savingsPlanId"]
    ctx.on_cleanup(lambda: _safe_delete_queued(ctx, plan_id1))

    resp2 = sp.create_savings_plan(**kwargs)
    plan_id2 = resp2["savingsPlanId"]
    # Registration MUST precede the dedup assertion: a failed dedup is precisely the case that
    # leaks a second, distinct queued plan with no cleanup at all.
    if plan_id2 != plan_id1:
        ctx.on_cleanup(lambda: _safe_delete_queued(ctx, plan_id2))

    assert plan_id1 == plan_id2, f"idempotent create returned different ids: {plan_id1} vs {plan_id2}"

    described = sp.describe_savings_plans(savingsPlanIds=[plan_id1])["savingsPlans"]
    assert len(described) == 1, f"expected exactly one plan record for {plan_id1}, got {len(described)}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
