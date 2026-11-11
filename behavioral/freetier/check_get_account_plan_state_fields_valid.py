"""get-account-plan-state-fields-valid."""

from __future__ import annotations

import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-account-plan-state-fields-valid"
GROUP = "state"
SERVICES = ["freetier"]

_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountPlanState returns a well-formed plan record with valid enum values and an
    accountId matching the caller's own account -- or, for an account with no Free Tier plan
    record provisioned, the documented ResourceNotFoundException naming that exact account."""
    freetier = ctx.client("freetier")
    caller_account = ctx.client("sts").get_caller_identity()["Account"]

    try:
        resp = freetier.get_account_plan_state()
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", error
        assert error["Message"] == f"Missing data for account: {caller_account}", error
        return

    assert resp["accountPlanType"] in ("FREE", "PAID"), resp["accountPlanType"]
    assert resp["accountPlanStatus"] in ("NOT_STARTED", "ACTIVE", "EXPIRED"), resp[
        "accountPlanStatus"
    ]
    account_id = resp["accountId"]
    assert _ACCOUNT_ID_RE.match(account_id), f"malformed accountId: {account_id!r}"
    assert account_id == caller_account, (account_id, caller_account)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
