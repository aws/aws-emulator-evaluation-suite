"""list-assessments-invalid-catalog-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-assessments-invalid-catalog-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]
CATALOG_PATTERN = r"^(?![.-])(?!.*[.-]{2})(?![0-9]+\.[0-9.]+$)[a-zA-Z0-9.-]{1,47}(?<![.-])$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAssessments refuses the Catalog 'AWS Marketplace' (with a space) with ValidationException and
    its exact message, while 'AWSMarketplace' returns an AssessmentSummaryList.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    code, msg = _error_code(lambda: mp.list_assessments(Catalog="AWS Marketplace"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == (
        f"[Requested catalog 'AWS Marketplace' is invalid. It should match with {CATALOG_PATTERN}.]"
    ), msg

    resp = mp.list_assessments(Catalog="AWSMarketplace", MaxResults=1)
    assert "AssessmentSummaryList" in resp


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
