"""list-agreement-cancellation-requests-maxresults-respected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "list-agreement-cancellation-requests-maxresults-respected"
GROUP = "list-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAgreementCancellationRequests with maxResults=3 and a status filter returns a list of at most
    3 items, and an empty page carries no nextToken.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    resp = mpa.list_agreement_cancellation_requests(
        partyType="Proposer", status="REJECTED", maxResults=3
    )
    items = resp["items"]
    assert isinstance(items, list), f"items was not a list, got {type(items).__name__}"
    assert len(items) <= 3, f"maxResults=3 but got {len(items)} items"
    if len(items) < 1:
        assert not resp.get("nextToken"), (
            f"no items returned but a nextToken was still present: {resp.get('nextToken')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
