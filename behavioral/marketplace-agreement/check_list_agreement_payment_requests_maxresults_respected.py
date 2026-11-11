"""list-agreement-payment-requests-maxresults-respected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-agreement-payment-requests-maxresults-respected"
GROUP = "list-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAgreementPaymentRequests returns an items list of at most maxResults for each party type, and
    a maxResults outside 1-50 is refused with ValidationException and its exact message.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    for party_type in ("Proposer", "Acceptor"):
        resp = mpa.list_agreement_payment_requests(partyType=party_type, maxResults=2)
        items = resp["items"]
        assert isinstance(items, list), f"items was not a list for partyType={party_type}"
        assert len(items) <= 2, f"maxResults=2 but got {len(items)} items for partyType={party_type}"

        try:
            mpa.list_agreement_payment_requests(partyType=party_type, maxResults=51)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message")
            want = ("ValidationException", "Provided max results is invalid.")
            assert (code, message) == want, (
                f"maxResults=51 (partyType={party_type}): expected {want!r}, "
                f"got {(code, message)!r}"
            )
        else:
            raise AssertionError(
                f"maxResults=51 is outside the documented 1-50 range but was accepted for "
                f"partyType={party_type}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
