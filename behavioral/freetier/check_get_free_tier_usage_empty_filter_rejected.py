"""get-free-tier-usage-empty-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-free-tier-usage-empty-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Expression with no root operator set at all is rejected with ValidationException; the
    same call shape with a real root operator still succeeds, so the rejection is attributable to
    the missing operator and not to anything else about the request."""
    freetier = ctx.client("freetier")

    # Positive control: a well-formed filter on the same call shape succeeds.
    control = freetier.get_free_tier_usage(
        filter={"Dimensions": {"Key": "REGION", "Values": ["us-east-1"], "MatchOptions": ["EQUALS"]}},
        maxResults=10,
    )
    assert isinstance(control["freeTierUsages"], list), control

    error = _error(lambda: freetier.get_free_tier_usage(filter={}, maxResults=10))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "[Message = Only one root operator is allowed for each expression: And, Or, Not, Dimensions]"
    ), error


def _error(fn):
    """Call fn(); return its ClientError's Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects an empty filter, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
