"""get-free-tier-usage-dimension-values-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-free-tier-usage-dimension-values-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFreeTierUsage with a Dimensions value "[Amazon!EC2]" outside the allowed charset fails with
    ValidationException and the exact pattern message, while the same filter with an allowed value returns a
    usage list."""
    freetier = ctx.client("freetier")

    invalid_filter = {
        "Dimensions": {
            "Key": "SERVICE",
            "Values": ["Amazon!EC2"],
            "MatchOptions": ["CONTAINS"],
        }
    }
    error = _error(lambda: freetier.get_free_tier_usage(filter=invalid_filter, maxResults=10))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "1 validation error detected: Value '[Amazon!EC2]' at 'filter.dimensions.values' "
        "failed to satisfy constraint: Member must satisfy constraint: [Member must have length "
        "less than or equal to 20, Member must have length greater than or equal to 1, Member "
        "must satisfy regular expression pattern: [ a-zA-Z0-9\\-\\:\\.\\_\\/\\,\\$\\(\\)]*]"
    ), error

    valid_filter = {
        "Dimensions": {
            "Key": "SERVICE",
            "Values": ["Amazon-EC2"],
            "MatchOptions": ["CONTAINS"],
        }
    }
    control = freetier.get_free_tier_usage(filter=valid_filter, maxResults=10)
    assert isinstance(control["freeTierUsages"], list), control


def _error(fn):
    """Call fn(); return its ClientError's Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected ValidationException, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
