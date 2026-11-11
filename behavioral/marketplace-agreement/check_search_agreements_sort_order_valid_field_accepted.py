"""search-agreements-sort-order-valid-field-accepted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-agreements-sort-order-valid-field-accepted"
GROUP = "list-semantics"
SERVICES = ["marketplace-agreement"]


def _sorted_by(items, field, reverse):
    values = [item[field] for item in items if item.get(field) is not None]
    return values == sorted(values, reverse=reverse)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchAgreements orders pages by sortBy=EndTime, and by StartTime/LastUpdateTime when scoped to
    PartyType=Proposer, while StartTime scoped to PartyType=Acceptor is refused with ValidationException.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    by_end_time = mpa.search_agreements(
        filters=[
            {"name": "AgreementType", "values": ["PurchaseAgreement"]},
            {"name": "PartyType", "values": ["Acceptor"]},
        ],
        sort={"sortBy": "EndTime", "sortOrder": "DESCENDING"},
        maxResults=5,
    )
    end_time_items = by_end_time["agreementViewSummaries"]
    assert isinstance(end_time_items, list), f"expected a list, got {type(end_time_items)!r}"
    assert _sorted_by(end_time_items, "endTime", reverse=True), (
        f"sortBy=EndTime DESCENDING not honored: {[i.get('endTime') for i in end_time_items]}"
    )

    by_start_time = mpa.search_agreements(
        filters=[
            {"name": "AgreementType", "values": ["PurchaseAgreement"]},
            {"name": "PartyType", "values": ["Proposer"]},
        ],
        sort={"sortBy": "StartTime", "sortOrder": "ASCENDING"},
        maxResults=5,
    )
    start_time_items = by_start_time["agreementViewSummaries"]
    assert isinstance(start_time_items, list), f"expected a list, got {type(start_time_items)!r}"
    assert _sorted_by(start_time_items, "startTime", reverse=False), (
        f"sortBy=StartTime ASCENDING not honored: {[i.get('startTime') for i in start_time_items]}"
    )

    by_last_update_time = mpa.search_agreements(
        filters=[
            {"name": "AgreementType", "values": ["PurchaseAgreement"]},
            {"name": "PartyType", "values": ["Proposer"]},
        ],
        sort={"sortBy": "LastUpdateTime", "sortOrder": "DESCENDING"},
        maxResults=5,
    )
    last_update_items = by_last_update_time["agreementViewSummaries"]
    assert isinstance(last_update_items, list), f"expected a list, got {type(last_update_items)!r}"

    # Negative control: the model reserves StartTime/LastUpdateTime for PartyType=Proposer.
    # The identical sort request scoped to Acceptor instead must be rejected, proving the
    # PartyType restriction is enforced rather than merely documented.
    bad = _error_code(
        lambda: mpa.search_agreements(
            filters=[
                {"name": "AgreementType", "values": ["PurchaseAgreement"]},
                {"name": "PartyType", "values": ["Acceptor"]},
            ],
            sort={"sortBy": "StartTime", "sortOrder": "ASCENDING"},
            maxResults=5,
        )
    )
    want = ("ValidationException", "Provided combination of filters is not supported.")
    assert bad == want, f"expected {want!r} for StartTime sort scoped to Acceptor, got {bad!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected ClientError, call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
