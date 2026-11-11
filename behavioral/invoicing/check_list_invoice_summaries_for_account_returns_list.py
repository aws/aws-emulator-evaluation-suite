"""list-invoice-summaries-for-account-returns-list."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-invoice-summaries-for-account-returns-list"
GROUP = "crud"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvoiceSummaries for the caller's account returns a list of its own
    summaries, while an out-of-range BillingPeriod.Month and MaxResults above 100 each
    fail with ValidationException and its exact message."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    now = datetime.datetime.now(datetime.timezone.utc)

    resp = invoicing.list_invoice_summaries(
        Selector={"ResourceType": "ACCOUNT_ID", "Value": account_id},
        Filter={"BillingPeriod": {"Month": now.month, "Year": now.year}},
        MaxResults=10,
    )
    assert isinstance(resp["InvoiceSummaries"], list), (
        f"expected InvoiceSummaries to be a list, got {resp.get('InvoiceSummaries')!r}"
    )
    for summary in resp["InvoiceSummaries"]:
        assert summary["AccountId"] == account_id, (
            f"summary AccountId {summary.get('AccountId')!r} != caller account {account_id!r}"
        )

    bad_month = _error(
        lambda: invoicing.list_invoice_summaries(
            Selector={"ResourceType": "ACCOUNT_ID", "Value": account_id},
            Filter={"BillingPeriod": {"Month": 13, "Year": now.year}},
            MaxResults=10,
        )
    )
    assert bad_month.get("Code") == "ValidationException", (
        f"BillingPeriod.Month=13 expected ValidationException, got {bad_month!r}"
    )
    expected_month_message = (
        "1 validation error detected: Value at 'filter.billingPeriod.month' failed to satisfy "
        "constraint: Member must have value less than or equal to 12"
    )
    assert bad_month.get("Message") == expected_month_message, (
        f"expected message {expected_month_message!r}, got {bad_month.get('Message')!r}"
    )

    bad_page = _error(
        lambda: invoicing.list_invoice_summaries(
            Selector={"ResourceType": "ACCOUNT_ID", "Value": account_id},
            Filter={"BillingPeriod": {"Month": now.month, "Year": now.year}},
            MaxResults=10000,
        )
    )
    assert bad_page.get("Code") == "ValidationException", (
        f"MaxResults=10000 expected ValidationException, got {bad_page!r}"
    )
    expected_page_message = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert bad_page.get("Message") == expected_page_message, (
        f"expected message {expected_page_message!r}, got {bad_page.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
