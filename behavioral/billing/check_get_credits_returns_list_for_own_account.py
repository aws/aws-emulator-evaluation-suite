"""get-credits-returns-list-for-own-account."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-credits-returns-list-for-own-account"
GROUP = "read-data"
SERVICES = ["billing"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetCredits for the caller's account returns a credits list whose every entry carries that
    accountId, an ENABLED/DISABLED status and both amounts, and a startDate after endDate fails
    with ValidationException "End date cannot be before start date."."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    now = datetime.now(timezone.utc)

    resp = billing.get_credits(
        accountId=account_id, startDate=now - timedelta(days=300), endDate=now
    )

    assert "credits" in resp, f"expected 'credits' key in response, got keys={list(resp)}"
    credits = resp["credits"]
    assert isinstance(credits, list), f"expected credits to be a list, got {type(credits)}"
    for credit in credits:
        assert credit["accountId"] == account_id, (
            f"credit {credit.get('creditId')}: expected accountId={account_id}, "
            f"got {credit.get('accountId')}"
        )
        assert credit["creditStatus"] in ("ENABLED", "DISABLED"), (
            f"credit {credit.get('creditId')}: unexpected creditStatus "
            f"{credit.get('creditStatus')!r}"
        )
        assert credit["remainingAmount"] is not None, (
            f"credit {credit.get('creditId')} missing remainingAmount"
        )
        assert credit["initialAmount"] is not None, (
            f"credit {credit.get('creditId')} missing initialAmount"
        )

    code, message = _error(
        lambda: billing.get_credits(
            accountId=account_id, startDate=now, endDate=now - timedelta(days=300)
        )
    )
    assert code == "ValidationException", code
    assert message == "End date cannot be before start date.", message


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
