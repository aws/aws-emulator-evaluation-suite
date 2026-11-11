"""list-tags-for-resource-invalid-arn-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-invalid-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region
_BAD_ARN = "not-an-arn-at-all"  # fails the ARN pattern entirely


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        "expected ListTagsForResource with a malformed ARN to be rejected, but it "
        f"succeeded and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ResourceARN that does not match the required ARN pattern is rejected with
    IllegalArgumentException, and a real quota ARN's tag listing keeps returning
    the same result before and after (positive control / effect absent)."""
    sq = ctx.client("service-quotas")

    try:
        quota = sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)["Quota"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchResourceException":
            raise AssertionError(
                "no applied quota ARN is available for "
                f"{_SERVICE_CODE}/{_QUOTA_CODE} in this account/region -- no real "
                "resource to use as the positive control"
            )
        raise
    arn = quota.get("QuotaArn")
    if not arn:
        raise AssertionError(f"applied quota for {_SERVICE_CODE}/{_QUOTA_CODE} has no QuotaArn")

    before = sq.list_tags_for_resource(ResourceARN=arn)["Tags"]

    code, message = _error_code(lambda: sq.list_tags_for_resource(ResourceARN=_BAD_ARN))
    assert code == "IllegalArgumentException", (
        f"expected IllegalArgumentException for a malformed ResourceARN, got {code!r}"
    )
    expected = "The request failed because you provided an illegal value for a parameter."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = sq.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert after == before, "the real resource's tags changed after the malformed-ARN call"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
