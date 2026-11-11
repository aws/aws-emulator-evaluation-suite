"""get-credit-allocation-history-returns-list-for-own-account."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-credit-allocation-history-returns-list-for-own-account"
GROUP = "read-data"
SERVICES = ["billing"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCreditAllocationHistory succeeds for a valid startDate<=endDate range
    on the caller's own account (structural response contract), and rejects
    a request where startDate is after endDate with ValidationException."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    now = datetime.now(timezone.utc)

    resp = billing.get_credit_allocation_history(
        accountId=account_id, startDate=now - timedelta(days=300), endDate=now
    )
    assert isinstance(resp.get("creditAllocationHistoryList"), list)
    assert isinstance(resp.get("partialResults"), bool)
    for entry in resp["creditAllocationHistoryList"]:
        assert entry["accountId"] == account_id

    code, message = _error(
        lambda: billing.get_credit_allocation_history(
            accountId=account_id, startDate=now, endDate=now - timedelta(days=300)
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "InvalidArgument: startDate (DetailedCode=startDate must be strictly before endDate "
        "(endDate is exclusive))"
    ), message


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
