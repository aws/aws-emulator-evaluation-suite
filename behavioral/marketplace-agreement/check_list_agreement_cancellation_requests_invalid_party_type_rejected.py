"""list-agreement-cancellation-requests-invalid-party-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-agreement-cancellation-requests-invalid-party-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAgreementCancellationRequests refuses a letters-only partyType other than Proposer/Acceptor
    with ValidationException and its exact message, while a valid partyType returns at most 5 items.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    bad = _error_code(
        lambda: mpa.list_agreement_cancellation_requests(partyType="NotAPartyType")
    )
    want = ("ValidationException", "Provided party type is invalid.")
    assert bad == want, f"expected {want!r}, got {bad!r}"

    # Positive control: a valid partyType value is accepted, returns a page (maybe empty), and
    # honors maxResults as an upper bound.
    resp = mpa.list_agreement_cancellation_requests(partyType="Acceptor", maxResults=5)
    items = resp["items"]
    assert isinstance(items, list), f"expected items to be a list, got {type(items).__name__}"
    assert len(items) <= 5, f"maxResults=5 but got {len(items)} items"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
