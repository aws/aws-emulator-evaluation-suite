"""describe-assessment-identifier-validation-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-assessment-identifier-validation-boundary"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]
ASSESSMENT_ID_PATTERN = (
    r"(^assessment-[a-zA-Z0-9]+$)|"
    r"(^arn:[a-zA-Z0-9-]+:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*::[a-zA-Z0-9-]+/Assessment/assessment-[a-zA-Z0-9]+$)"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAssessment refuses an identifier matching neither the short nor the ARN form with
    ValidationException, and a well-formed unknown 'assessment-<alnum>' id with ResourceNotFoundException,
    each with its exact message.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    code, msg = _error_code(
        lambda: mp.describe_assessment(
            Catalog="AWSMarketplace", AssessmentIdentifier="not-a-valid-identifier"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == (
        "[Requested assessment identifier 'not-a-valid-identifier' is invalid. "
        f"It should match with {ASSESSMENT_ID_PATTERN}.]"
    ), msg

    missing_id = "assessment-" + ctx.unique_name("sim2realbehav").replace("-", "")
    code2, msg2 = _error_code(
        lambda: mp.describe_assessment(Catalog="AWSMarketplace", AssessmentIdentifier=missing_id)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert msg2 == f"Requested assessment '{missing_id}' does not exist.", msg2


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
