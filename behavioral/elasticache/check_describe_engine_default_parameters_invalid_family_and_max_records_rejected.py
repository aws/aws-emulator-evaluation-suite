"""describe-engine-default-parameters-invalid-family-and-max-records-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-engine-default-parameters-invalid-family-and-max-records-rejected"
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
    """DescribeEngineDefaultParameters refuses an unmodeled CacheParameterGroupFamily and a
    MaxRecords below 20 or above 100, each with InvalidParameterValue and its exact message,
    while a modeled family with a MaxRecords of 20 returns that family's own defaults."""
    ec = ctx.client("elasticache")

    code, message = _error(
        lambda: ec.describe_engine_default_parameters(CacheParameterGroupFamily="redis99"),
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "CacheParameterGroupFamily redis99 is not a valid parameter group family.", (
        f"unexpected message for family redis99: {message!r}"
    )

    code, message = _error(
        lambda: ec.describe_engine_default_parameters(
            CacheParameterGroupFamily="redis7", MaxRecords=19,
        ),
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Invalid value for max records. Must be between 20 and 100", (
        f"unexpected message for MaxRecords=19: {message!r}"
    )

    code, message = _error(
        lambda: ec.describe_engine_default_parameters(
            CacheParameterGroupFamily="redis7", MaxRecords=101,
        ),
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "Invalid value for max records. Must be between 20 and 100", (
        f"unexpected message for MaxRecords=101: {message!r}"
    )

    # Positive control: the modeled family redis7 at the lowest accepted MaxRecords succeeds
    # and names the same family back, paging no more than what was asked for.
    accepted = ec.describe_engine_default_parameters(
        CacheParameterGroupFamily="redis7", MaxRecords=20,
    )["EngineDefaults"]
    assert accepted["CacheParameterGroupFamily"] == "redis7", (
        f"expected the response to echo the requested family, got {accepted!r}"
    )
    assert len(accepted["Parameters"]) <= 20, (
        f"MaxRecords=20 must page at most 20 parameters, got {len(accepted['Parameters'])}"
    )
    assert accepted["Parameters"], "expected redis7's default parameters, got an empty page"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
