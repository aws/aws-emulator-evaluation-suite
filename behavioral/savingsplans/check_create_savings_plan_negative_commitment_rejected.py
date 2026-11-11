"""create-savings-plan-negative-commitment-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-savings-plan-negative-commitment-rejected"
GROUP = "overly-permissive"
SERVICES = ["savingsplans"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSavingsPlan rejects a negative hourly commitment against a real, existing offering
    with ValidationException and creates nothing, while the identical offering with a valid
    commitment (the positive control) is purchased successfully into the 'queued' state."""
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    purchase_time = (datetime.now(timezone.utc) + timedelta(days=200)).replace(microsecond=0)

    # Sibling checks create queued plans in this account concurrently, so the absence is read off
    # every plan that is new against `before_ids`, read before the refused call: none may carry
    # this run's marker tag, a commitment below the 0.001 floor, or the refused call's offering id
    # together with its purchase time as the plan's start.
    run_marker = ctx.unique_name("sim2real-neg-commit-")
    before_ids = {p["savingsPlanId"] for p in _all_plans(sp)}

    err = _error(
        lambda: sp.create_savings_plan(
            savingsPlanOfferingId=offering_id,
            commitment="-1",
            purchaseTime=purchase_time,
            tags={"sim2real-check": CHECK, "sim2real-run": run_marker},
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException for commitment=-1, got {err!r}"
    assert err["Message"] == "'commitment' cannot be less than 0.001", f"unexpected create_neg message: {err['Message']!r}"

    new_plans = [p for p in _all_plans(sp) if p["savingsPlanId"] not in before_ids]
    created = [
        p
        for p in new_plans
        if (p.get("tags") or {}).get("sim2real-run") == run_marker
        or float(p.get("commitment") or 0) < 0.001
        or (p.get("offeringId") == offering_id and _start(p) == purchase_time)
    ]
    assert not created, f"a rejected CreateSavingsPlan call must not create a plan, found {created!r}"

    # Positive control: the same offering with a valid commitment succeeds.
    plan_id = _create_queued_plan(ctx, commitment="0.001")
    plan = sp.describe_savings_plans(savingsPlanIds=[plan_id])["savingsPlans"][0]
    assert plan["state"] == "queued", f"expected positive-control plan {plan_id!r} to be 'queued', got {plan['state']!r}"


def _start(plan) -> datetime | None:
    """The plan's `start` ("The start time", e.g. 2027-05-22T10:11:12.000Z) to the second, in UTC."""
    raw = plan.get("start")
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).replace(microsecond=0)


def _all_plans(sp) -> list:
    """Every savings plan DescribeSavingsPlans lists, across all pages."""
    plans, token = [], None
    while True:
        page = sp.describe_savings_plans(**({"nextToken": token} if token else {}))
        plans.extend(page.get("savingsPlans", []))
        token = page.get("nextToken")
        if not token:
            return plans


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
        "tags": {"sim2real-check": CHECK},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
