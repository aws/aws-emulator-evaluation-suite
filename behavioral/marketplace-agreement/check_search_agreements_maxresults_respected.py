"""search-agreements-maxresults-respected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-agreements-maxresults-respected"
GROUP = "list-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchAgreements returns at most maxResults summaries with no nextToken on a short page, and a
    maxResults outside [1, 50] sent past client-side validation is refused with ValidationException.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    filters = [
        {"name": "AgreementType", "values": ["PurchaseAgreement"]},
        {"name": "PartyType", "values": ["Acceptor"]},
    ]

    resp = mpa.search_agreements(filters=filters, maxResults=1)
    items = resp["agreementViewSummaries"]
    assert isinstance(items, list)
    assert len(items) <= 1, f"maxResults=1 but got {len(items)} items"
    if len(items) < 1:
        assert not resp.get("nextToken"), "no items returned but a nextToken was still present"

    raw = _unvalidated_client(ctx)

    # Positive control through the raw (validation-disabled) client: proves the ValidationException
    # asserted below comes from the server rejecting the out-of-range value, not from the raw
    # client being broken in some other way.
    control = raw.search_agreements(filters=filters, maxResults=1)
    assert isinstance(control["agreementViewSummaries"], list)

    # maxResults is modelled as an integer in [1, 50] -- a fixed API constant, not an
    # account-adjustable quota -- so a value outside that range must be rejected, not clamped.
    for bad_max_results in (0, 51):
        got = _rejected_with(
            lambda mr=bad_max_results: raw.search_agreements(filters=filters, maxResults=mr)
        )
        want = ("ValidationException", "Provided max results is invalid.")
        assert got == want, (
            f"maxResults={bad_max_results} is outside the modelled [1,50] range: expected "
            f"{want!r}, got {got!r}"
        )


def _unvalidated_client(ctx):
    return ctx.client(
        "marketplace-agreement", region="us-east-1", config=Config(parameter_validation=False)
    )


def _rejected_with(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; expected it to be rejected")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
