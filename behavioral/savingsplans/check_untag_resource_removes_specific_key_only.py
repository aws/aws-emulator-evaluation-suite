"""untag-resource-removes-specific-key-only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-removes-specific-key-only"
GROUP = "tagging"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the named tag key(s), leaving the remaining tags on the resource
    untouched."""
    sp = ctx.client("savingsplans")
    plan_id = _create_queued_plan(ctx, commitment="0.001")
    arn = sp.describe_savings_plans(savingsPlanIds=[plan_id])["savingsPlans"][0]["savingsPlanArn"]

    sp.tag_resource(resourceArn=arn, tags={"keep": "1", "drop": "2"})
    tags_before = sp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_before.get("keep") == "1" and tags_before.get("drop") == "2", (
        f"expected TagResource to have set both keep and drop, got {tags_before}"
    )

    sp.untag_resource(resourceArn=arn, tagKeys=["drop"])

    # Real Savings Plans resources carry a reserved `aws:`-prefixed system tag this account cannot
    # set or clear via TagResource/UntagResource, so the expected post-untag set is derived from the
    # actually-observed pre-untag set (minus the dropped key) rather than a hardcoded literal --
    # that way the assertion still catches UntagResource touching anything other than the named key.
    tags_after = sp.list_tags_for_resource(resourceArn=arn)["tags"]
    expected = {k: v for k, v in tags_before.items() if k != "drop"}
    assert tags_after == expected, (
        f"expected UntagResource to remove only 'drop', leaving {expected}, got {tags_after}"
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


def _create_queued_plan(ctx, commitment: str = "0.001", client_token: str | None = None) -> str:
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    kwargs = {
        "savingsPlanOfferingId": offering_id,
        "commitment": commitment,
        "purchaseTime": _future_purchase_time(),
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
