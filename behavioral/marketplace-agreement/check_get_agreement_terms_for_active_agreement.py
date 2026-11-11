"""get-agreement-terms-for-active-agreement."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-agreement-terms-for-active-agreement"
GROUP = "state"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a real ACTIVE agreement the caller participates in, GetAgreementTerms returns a
    non-empty list of accepted terms and DescribeAgreement's summary (status, proposer/acceptor)
    is consistent with what SearchAgreements reported for the same agreementId."""
    # marketplace-agreement answers only in us-east-1, whatever the run's region; ctx.client's
    # region override pins the endpoint and the signing region on every target.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")
    agreement = _find_active_agreement(mpa)
    if agreement is None:
        raise AssertionError(
            "no ACTIVE AWS Marketplace agreement exists for this caller; requires a real "
            "purchased/subscribed product (buyer or seller side) to exercise agreement-terms "
            "retrieval end to end -- closed by seeding a live agreement fixture"
        )

    terms = mpa.get_agreement_terms(agreementId=agreement["agreementId"])
    assert isinstance(terms["acceptedTerms"], list)
    assert len(terms["acceptedTerms"]) >= 1, "an ACTIVE agreement must have at least one accepted term"

    described = mpa.describe_agreement(agreementId=agreement["agreementId"])
    assert described["status"] == "ACTIVE"
    assert described["agreementId"] == agreement["agreementId"]


def _find_active_agreement(mpa):
    # SearchAgreements requires a PartyType filter together with AgreementType; Status can be
    # combined with both for the Acceptor party type.
    resp = mpa.search_agreements(
        filters=[
            {"name": "AgreementType", "values": ["PurchaseAgreement"]},
            {"name": "PartyType", "values": ["Acceptor"]},
            {"name": "Status", "values": ["ACTIVE"]},
        ],
        maxResults=1,
    )
    items = resp.get("agreementViewSummaries", [])
    return items[0] if items else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
