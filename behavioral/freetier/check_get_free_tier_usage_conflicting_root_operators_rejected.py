"""get-free-tier-usage-conflicting-root-operators-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-free-tier-usage-conflicting-root-operators-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFreeTierUsage rejects an Expression that sets more than one root operator (And + Or)."""
    freetier = ctx.client("freetier")

    region_dim = {"Dimensions": {"Key": "REGION", "Values": ["us-east-1"], "MatchOptions": ["EQUALS"]}}
    other_region_dim = {"Dimensions": {"Key": "REGION", "Values": ["us-west-2"], "MatchOptions": ["EQUALS"]}}
    conflicting_filter = {"And": [region_dim], "Or": [other_region_dim]}

    # Positive control before the rejected call: a filter with exactly one root operator succeeds.
    before = freetier.get_free_tier_usage(filter=region_dim)
    assert isinstance(before["freeTierUsages"], list), type(before["freeTierUsages"])

    error = _error(lambda: freetier.get_free_tier_usage(filter=conflicting_filter))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "[Message = Only one root operator is allowed for each expression: And, Or, Not, Dimensions]"
    ), error

    # Effect absent + control: the rejected And+Or request left the single-operator query unaffected.
    after = freetier.get_free_tier_usage(filter=region_dim)
    assert len(after["freeTierUsages"]) == len(before["freeTierUsages"]), (
        len(after["freeTierUsages"]),
        len(before["freeTierUsages"]),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
