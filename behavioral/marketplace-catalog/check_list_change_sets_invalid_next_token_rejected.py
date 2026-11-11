"""list-change-sets-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-change-sets-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListChangeSets without a NextToken succeeds, and a NextToken containing a space is refused with
    ValidationException "[Requested page token is invalid.]".
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    resp = mp.list_change_sets(Catalog="AWSMarketplace", MaxResults=1)
    assert "ChangeSetSummaryList" in resp

    code, msg = _error_code(
        lambda: mp.list_change_sets(Catalog="AWSMarketplace", NextToken="not a valid token !!")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == "[Requested page token is invalid.]", msg


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
