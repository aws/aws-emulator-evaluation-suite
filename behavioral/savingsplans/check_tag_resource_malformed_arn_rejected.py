"""tag-resource-malformed-arn-rejected."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["savingsplans"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on the check's own Savings Plan is reflected by ListTagsForResource, a malformed ARN is refused with
    ValidationException (exact message), and a well-formed missing ARN with ResourceNotFoundException (exact message).
    """
    sp = ctx.client("savingsplans")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: a well-formed ARN for a Savings Plan that actually exists succeeds.
    plan_id = _create_queued_plan(ctx)
    real_arn = sp.describe_savings_plans(savingsPlanIds=[plan_id])["savingsPlans"][0]["savingsPlanArn"]
    sp.tag_resource(resourceArn=real_arn, tags={"sim2real-env": "behavioral-check"})
    tags_after = sp.list_tags_for_resource(resourceArn=real_arn)["tags"]
    # Compare only the tag TagResource just set, not the whole map: the account may already
    # attach its own default tags (e.g. a tag policy) to a freshly created resource.
    assert tags_after.get("sim2real-env") == "behavioral-check", (
        f"expected TagResource against a real, existing plan to succeed, got tags {tags_after}"
    )

    malformed_arn = "not-an-arn"
    err = _error(lambda: sp.tag_resource(resourceArn=malformed_arn, tags={"k": "v"}))
    assert err["Code"] == "ValidationException", f"expected ValidationException for a malformed ARN, got {err!r}"
    assert err["Message"] == (
        "1 validation error detected: Value 'not-an-arn' at 'originalRequest.resourceArn' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        r"^arn:aws([-a-z]*)?:[a-z]+:([a-z]{2}-[a-z]+-\d{1}|):(\d{12}):savingsplan\/"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
    ), f"unexpected tag_malformed message: {err['Message']!r}"

    # A well-formed ARN pattern (caller's own account) for a Savings Plan that was never created --
    # passes pattern validation, fails at resource lookup instead.
    well_formed_missing_arn = f"arn:aws:savingsplans::{account_id}:savingsplan/{uuid.uuid4()}"
    err2 = _error(lambda: sp.tag_resource(resourceArn=well_formed_missing_arn, tags={"k": "v"}))
    assert err2["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent ARN, got {err2!r}"
    )
    assert err2["Message"] == f"Resource with resourceArn: {well_formed_missing_arn} doesn't exist", f"unexpected tag_missing message: {err2['Message']!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_cheap_offering(ctx) -> str:
    # Pin the search to the shortest term the offering catalog sells (`durations` is "The
    # duration, in seconds" per the savingsplans Smithy model; 31536000 = 1 year), bounding the
    # residual cost if cleanup ever fails to ~$8.76 at commitment="0.001" per hour, versus ~$26.28
    # for a 3-year term.
    sp = ctx.client("savingsplans")
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


def _create_queued_plan(ctx) -> str:
    sp = ctx.client("savingsplans")
    offering_id = _get_cheap_offering(ctx)
    purchase_time = datetime.now(timezone.utc) + timedelta(days=200)
    # DeleteQueuedSavingsPlan is the only cleanup that works here, and only while the plan is
    # still `queued` -- which is why purchaseTime is 200 days out.
    resp = sp.create_savings_plan(
        savingsPlanOfferingId=offering_id,
        commitment="0.001",
        purchaseTime=purchase_time,
    )
    plan_id = resp["savingsPlanId"]
    ctx.on_cleanup(lambda: _safe_delete_queued(ctx, plan_id))
    return plan_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
