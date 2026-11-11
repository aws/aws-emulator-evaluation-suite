"""get-free-tier-usage-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-free-tier-usage-max-results-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """maxResults above the documented maximum of 1000 is rejected with ValidationException,
    while an in-range value is accepted."""
    freetier = ctx.client("freetier")

    control = freetier.get_free_tier_usage(maxResults=1000)
    assert isinstance(control["freeTierUsages"], list), control

    error = _error(lambda: freetier.get_free_tier_usage(maxResults=1500))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "1 validation error detected: Value '1500' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 1000"
    ), error


def _error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
