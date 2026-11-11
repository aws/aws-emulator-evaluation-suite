"""describe-change-set-id-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-change-set-id-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]
CATALOG_PATTERN = r"^(?![.-])(?!.*[.-]{2})(?![0-9]+\.[0-9.]+$)[a-zA-Z0-9.-]{1,47}(?<![.-])$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeChangeSet refuses a Catalog outside the pattern with ValidationException and a valid but
    nonexistent ChangeSetId with ResourceNotFoundException, each with its exact message; ListChangeSets
    still works.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    code, msg = _error_code(
        lambda: mp.describe_change_set(Catalog="AWS_Marketplace", ChangeSetId="abc123")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == (
        f"[Requested catalog 'AWS_Marketplace' is invalid. It should match with {CATALOG_PATTERN}.]"
    ), msg

    missing_id = "sim2real" + ctx.unique_name("").replace("-", "")[:16]
    code2, msg2 = _error_code(
        lambda: mp.describe_change_set(Catalog="AWSMarketplace", ChangeSetId=missing_id)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert msg2 == f"Requested change set '{missing_id}' does not exist.", msg2

    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp, (
        "positive control: the account and credentials must otherwise be healthy for "
        "marketplace-catalog, or the two rejections above are indistinguishable from "
        "everything being denied"
    )


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
