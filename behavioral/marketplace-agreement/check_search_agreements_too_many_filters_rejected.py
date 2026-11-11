"""search-agreements-too-many-filters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-agreements-too-many-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SearchAgreements rejects a filters list beyond the documented maximum of 10 entries with
    ValidationException, while an otherwise-identical call with a compliant filter list (<=10)
    succeeds -- proving the rejection is tied to the filter count, not the fact of filtering."""
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    # A Proposer caller may combine AgreementType with any of the other documented filters, so
    # a Proposer-scoped search is unrestricted by the "supported combination" rule -- letting the
    # 10-item count cap (not filter combination semantics) be the sole thing under test.
    base_filters = [
        {"name": "AgreementType", "values": ["PurchaseAgreement"]},
        {"name": "PartyType", "values": ["Proposer"]},
        {"name": "Status", "values": ["ACTIVE"]},
        {"name": "ResourceType", "values": ["SaaSProduct"]},
        {"name": "AcceptorAccountId", "values": ["123456789012"]},
        {"name": "OfferId", "values": ["offer-sim2real0000"]},
        {"name": "ResourceIdentifier", "values": ["prod-sim2real0000"]},
        {"name": "OfferSetId", "values": ["offerset-sim2real0"]},
        {"name": "EndTimeBehaviorType", "values": ["RENEW"]},
        {"name": "InitialAgreementId", "values": ["agmt-sim2real00000"]},
    ]
    too_many_filters = base_filters + [
        {"name": "LicenseArn", "values": ["arn:aws:license-manager:us-east-1:123456789012:license:l-sim2real0"]}
    ]
    bad = _error_code(lambda: mpa.search_agreements(filters=too_many_filters))
    want = ("ValidationException", "Provided filters is invalid.")
    assert bad == want, f"expected {want!r}, got {bad!r}"

    # Positive control: exactly 10 filters (the documented max) is accepted and returns a page.
    resp = mpa.search_agreements(filters=base_filters, maxResults=5)
    assert isinstance(resp["agreementViewSummaries"], list), (
        f"expected a compliant 10-filter search to succeed with a list, got {resp['agreementViewSummaries']!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
