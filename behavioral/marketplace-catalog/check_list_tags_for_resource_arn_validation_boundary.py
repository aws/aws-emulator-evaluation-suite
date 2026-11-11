"""list-tags-for-resource-arn-validation-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-arn-validation-boundary"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]
ARN_PATTERN = r"^arn:[\w+=/,.@-]+:aws-marketplace:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource refuses a malformed ARN with ValidationException and its exact message, but a
    well-formed ARN of an entity the caller does not own with AccessDeniedException; ListChangeSets
    still works.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    bad_arn = "arn:aws:aws-marketplace" # truncated / malformed, missing required segments
    code, msg = _error_code(lambda: mp.list_tags_for_resource(ResourceArn=bad_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {msg}"
    assert msg == f"[Requested resource arn '{bad_arn}' is invalid. It should match with {ARN_PATTERN}.]", msg

    good_but_missing_arn = (
        "arn:aws:aws-marketplace:us-east-1:111122223333:AWSMarketplace/ContainerProduct/"
        + ctx.unique_name("sim2real-behav-")
    )
    # message varies: AWS embeds the calling principal's ARN, which the check does not create.
    code2, msg2 = _error_code(lambda: mp.list_tags_for_resource(ResourceArn=good_but_missing_arn))
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}: {msg2}"

    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp, "service must remain functional; the two rejections above are ARN-specific, not a broken client"


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
