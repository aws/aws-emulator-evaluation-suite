"""create-savings-plan-concurrent-same-client-token-dedup."""
from __future__ import annotations

import concurrent.futures
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-savings-plan-concurrent-same-client-token-dedup"
GROUP = "concurrency"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racing CreateSavingsPlan calls sharing one clientToken and identical parameters all
    dedup to exactly one savingsPlanId, and only one plan record actually exists afterward --
    the idempotency-token contract must hold under contention, not just sequentially."""
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    purchase_time = datetime.now(timezone.utc) + timedelta(days=200)
    token = str(uuid.uuid4())

    def _racer():
        # Residual cost if cleanup does not run: the plan activates at purchaseTime and bills
        # `commitment` per hour for the full term, with no further cancel path once it is active.
        # DeleteQueuedSavingsPlan ("Deletes the queued purchase for the specified Savings Plan") is the
        # ONLY cleanup that works here, and only while the plan is still `queued` -- which is why
        # purchaseTime is 200 days out. ReturnSavingsPlan ("Returns the specified Savings Plan") has
        # only a narrow post-purchase return window and is not usable on a queued plan.
        resp = sp.create_savings_plan(
            savingsPlanOfferingId=offering_id,
            commitment="0.001",
            purchaseTime=purchase_time,
            clientToken=token,
            tags={"sim2real-env": "behavioral-check"},
        )
        return resp["savingsPlanId"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_racer) for _ in range(6)]

    # Register cleanup for every id a racer returned BEFORE asserting dedup: a failed dedup is
    # exactly the case that would otherwise leave extra queued Savings Plans behind. A racer's
    # exception is re-raised below by `f.result()`.
    for _pid in sorted({f.result() for f in futures if not f.exception()}):
        ctx.on_cleanup(lambda pid=_pid: _safe_delete_queued(ctx, pid))

    ids = [f.result() for f in futures]
    unique_ids = set(ids)
    assert len(unique_ids) == 1, f"expected all racers to dedup to one plan id, got {unique_ids}"
    plan_id = unique_ids.pop()

    described = sp.describe_savings_plans(savingsPlanIds=[plan_id])["savingsPlans"]
    assert len(described) == 1


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
