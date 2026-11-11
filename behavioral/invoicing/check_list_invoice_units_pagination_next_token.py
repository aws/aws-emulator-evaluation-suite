"""list-invoice-units-pagination-next-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-invoice-units-pagination-next-token"
GROUP = "crud"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvoiceUnits with MaxResults=1 returns the one filtered unit with no
    NextToken, and paginating the unfiltered listing one unit per page yields
    duplicate-free ARNs that include the unit."""
    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    # Without AWS Organizations member accounts or billing-transfer
    # authorizations, only the caller's own account id is a valid Rule
    # dimension -- and an account can be assigned to at most one invoice
    # unit at a time. That means a second, independently valid invoice unit
    # can't be created, so multi-unit pagination is exercised against
    # whatever unfiltered set of units already exists instead of two
    # purpose-built ones.
    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[
            {"Key": "sim2real-env", "Value": "behavioral"},
            {"Key": "sim2real-owner", "Value": "invoicing-suite"},
        ],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    # Single-page contract: a filter matching exactly our 1 unit, with
    # MaxResults=1, returns that unit and no NextToken (nothing more to page).
    solo_page = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=1)
    assert len(solo_page["InvoiceUnits"]) == 1, (
        f"expected exactly 1 unit named {name!r} with MaxResults=1, got {solo_page['InvoiceUnits']!r}"
    )
    assert solo_page["InvoiceUnits"][0]["InvoiceUnitArn"] == arn, (
        f"expected the filtered page to return {arn!r}, got {solo_page['InvoiceUnits'][0]['InvoiceUnitArn']!r}"
    )
    assert not solo_page.get("NextToken"), "expected no NextToken once the 1-unit filtered selection is exhausted"

    # General pagination correctness: walk the unfiltered listing one unit
    # at a time via NextToken and confirm the traversal is duplicate-free and
    # terminates, and that our own unit is reachable within it.
    seen_arns = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = invoicing.list_invoice_units(**kwargs)
        pages += 1
        assert len(page["InvoiceUnits"]) <= 1, (
            f"MaxResults=1 must cap each page at 1 unit, got {len(page['InvoiceUnits'])} on page {pages}"
        )
        seen_arns.extend(u["InvoiceUnitArn"] for u in page["InvoiceUnits"])
        next_token = page.get("NextToken")
        if not next_token or pages > 500:
            break

    assert pages <= 500, "pagination did not terminate within a sane number of pages"
    assert len(seen_arns) == len(set(seen_arns)), "paginated traversal must not return duplicate ARNs across pages"
    assert arn in seen_arns, "the newly created unit must be reachable via full pagination"


def _safe_delete_invoice_unit(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("invoicing").delete_invoice_unit(InvoiceUnitArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

