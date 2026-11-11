"""get-account-plan-state-basic-shape."""

from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-plan-state-basic-shape"
GROUP = "state"
SERVICES = ["freetier"]

_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_PLAN_TYPES = {"FREE", "PAID"}
_PLAN_STATUSES = {"NOT_STARTED", "ACTIVE", "EXPIRED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountPlanState returns a well-formed accountId/plan-type/plan-status triple, or --
    for an account that has no Free Tier plan record provisioned yet -- the documented
    ResourceNotFoundException naming that exact account."""
    freetier = ctx.client("freetier")

    try:
        resp = freetier.get_account_plan_state()
    except ClientError as err:
        error = err.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", error
        sts = ctx.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        assert error["Message"] == f"Missing data for account: {account_id}", error
        return

    assert _ACCOUNT_ID_RE.match(resp["accountId"]), (
        f"malformed accountId: {resp['accountId']!r}"
    )
    assert resp["accountPlanType"] in _PLAN_TYPES, resp["accountPlanType"]
    assert resp["accountPlanStatus"] in _PLAN_STATUSES, resp["accountPlanStatus"]

    # accountPlanRemainingCredits is optional but, when present, must be a well-formed
    # MonetaryAmount (non-negative amount, USD unit).
    credits = resp.get("accountPlanRemainingCredits")
    if credits is not None:
        assert isinstance(credits["amount"], (int, float)), (
            f"non-numeric amount: {credits!r}"
        )
        assert credits["amount"] >= 0, f"negative credits amount: {credits!r}"
        assert credits["unit"] == "USD", f"unexpected currency unit: {credits!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
