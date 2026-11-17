"""describe-max-records-bounds-differ-by-operation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-max-records-bounds-differ-by-operation"
GROUP = "pagination"
SERVICES = ["elasticache"]


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCacheEngineVersions refuses a MaxRecords below 20 or above 100 with
    InvalidParameterValue naming that 20-100 range, while DescribeServiceUpdates accepts
    MaxRecords as low as 1 and names a 1-100 range in its own refusal above 100."""
    ec = ctx.client("elasticache")

    code, message = _error(lambda: ec.describe_cache_engine_versions(MaxRecords=19))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Invalid value for max records. Must be between 20 and 100", (
        f"unexpected message for MaxRecords=19: {message!r}"
    )

    code, message = _error(lambda: ec.describe_cache_engine_versions(MaxRecords=101))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Invalid value for max records. Must be between 20 and 100", (
        f"unexpected message for MaxRecords=101: {message!r}"
    )

    # Positive control: 20 is the lowest value DescribeCacheEngineVersions accepts.
    accepted = ec.describe_cache_engine_versions(MaxRecords=20)
    assert len(accepted.get("CacheEngineVersions", [])) == 20, (
        f"MaxRecords=20 should page exactly 20 engine versions, got "
        f"{len(accepted.get('CacheEngineVersions', []))}"
    )

    # Negative: DescribeServiceUpdates rejects the SAME too-high value with the SAME code,
    # but its exact message names a different lower bound.
    code, message = _error(lambda: ec.describe_service_updates(MaxRecords=101))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Invalid value for max records. Must be between 1 and 100", (
        f"unexpected message for DescribeServiceUpdates MaxRecords=101: {message!r}"
    )

    # Positive control: the value DescribeCacheEngineVersions refuses (19) is within
    # DescribeServiceUpdates' own, lower bound, so the SAME value is accepted here, and
    # pagination still caps the page at what was asked for.
    accepted = ec.describe_service_updates(MaxRecords=19)
    assert len(accepted.get("ServiceUpdates", [])) <= 19, (
        f"MaxRecords=19 must page at most 19 service updates, got "
        f"{len(accepted.get('ServiceUpdates', []))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
