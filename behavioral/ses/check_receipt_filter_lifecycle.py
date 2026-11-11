"""receipt-filter-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-filter-lifecycle"
GROUP = 'receipt-filter'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; skip elsewhere."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IP receipt filter round-trips through Create/List/Delete; a duplicate name is refused with
    AlreadyExists without overwriting the original, delete is idempotent, and the freed name is
    reusable."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    name = ctx.unique_name("sim2real-behav-filter-")
    conflicting_filter = {"Name": name, "IpFilter": {"Cidr": "198.51.100.0/24", "Policy": "Allow"}}

    ses.create_receipt_filter(
        Filter={"Name": name, "IpFilter": {"Cidr": "203.0.113.0/24", "Policy": "Block"}}
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_receipt_filter(FilterName=_n))

    filters = {f["Name"]: f for f in ses.list_receipt_filters()["Filters"]}
    assert name in filters, "receipt filter missing from ListReceiptFilters"
    assert filters[name]["IpFilter"]["Cidr"] == "203.0.113.0/24"
    assert filters[name]["IpFilter"]["Policy"] == "Block"

    err, msg = _err(lambda: ses.create_receipt_filter(Filter=conflicting_filter))
    assert err == "AlreadyExists", (
        f"expected AlreadyExists recreating an existing receipt filter, got {err!r}: {msg!r}"
    )
    expected_msg = f"Filter already exists: {name}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the refused create must not have overwritten the original filter's fields.
    filters_after_conflict = {f["Name"]: f for f in ses.list_receipt_filters()["Filters"]}
    assert name in filters_after_conflict, "original receipt filter disappeared after a rejected recreate"
    assert filters_after_conflict[name]["IpFilter"]["Cidr"] == "203.0.113.0/24", (
        f"rejected recreate changed the stored CIDR: {filters_after_conflict[name]['IpFilter']!r}"
    )
    assert filters_after_conflict[name]["IpFilter"]["Policy"] == "Block", (
        f"rejected recreate changed the stored policy: {filters_after_conflict[name]['IpFilter']!r}"
    )

    ses.delete_receipt_filter(FilterName=name)
    filters_after = {f["Name"]: f for f in ses.list_receipt_filters()["Filters"]}
    assert name not in filters_after, "receipt filter still present after delete"

    # Deleting a non-existent filter is idempotent, not an error.
    ses.delete_receipt_filter(FilterName=name)

    ses.create_receipt_filter(Filter=conflicting_filter)
    filters_final = {f["Name"]: f for f in ses.list_receipt_filters()["Filters"]}
    assert name in filters_final, "receipt filter missing after recreating a freed name"
    assert filters_final[name]["IpFilter"]["Cidr"] == "198.51.100.0/24", (
        f"recreated filter has the wrong CIDR: {filters_final[name]['IpFilter']!r}"
    )
    assert filters_final[name]["IpFilter"]["Policy"] == "Allow", (
        f"recreated filter has the wrong policy: {filters_final[name]['IpFilter']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
