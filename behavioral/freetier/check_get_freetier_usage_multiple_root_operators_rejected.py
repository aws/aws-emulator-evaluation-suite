"""get-freetier-usage-multiple-root-operators-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-freetier-usage-multiple-root-operators-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Expression with more than one root operator set is rejected; a single-root-operator filter still works."""
    freetier = ctx.client("freetier")

    region_dim = {"Dimensions": {"Key": "REGION", "Values": ["us-east-1"], "MatchOptions": ["EQUALS"]}}

    # Positive control: a filter with exactly one root operator ("Dimensions" alone) succeeds,
    # so the negative below cannot be confused with "this target rejects every filter".
    before = freetier.get_free_tier_usage(filter=region_dim, maxResults=5)
    assert isinstance(before.get("freeTierUsages", []), list)

    bad_expression = {
        "And": [region_dim],
        "Dimensions": {"Key": "SERVICE", "Values": ["AWSLambda"], "MatchOptions": ["EQUALS"]},
    }
    error = _error(lambda: freetier.get_free_tier_usage(filter=bad_expression))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "[Message = Only one root operator is allowed for each expression: And, Or, Not, Dimensions]"
    ), error

    # effect absent + control: the identical single-root-operator call is unaffected by the rejected request
    after = freetier.get_free_tier_usage(filter=region_dim, maxResults=5)
    assert len(after.get("freeTierUsages", [])) == len(before.get("freeTierUsages", []))


def _error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
