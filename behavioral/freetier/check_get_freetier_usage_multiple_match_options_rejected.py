"""get-freetier-usage-multiple-match-options-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-freetier-usage-multiple-match-options-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Dimensions filter with more than one MatchOption is rejected; a single MatchOption still works."""
    freetier = ctx.client("freetier")

    # REGION dimension value is filter content, not the client's operating region — any valid
    # AWS region works here, unrelated to ctx.region.
    good_expression = {
        "Dimensions": {"Key": "REGION", "Values": ["us-east-1"], "MatchOptions": ["EQUALS"]}
    }
    before = freetier.get_free_tier_usage(maxResults=1000, filter=good_expression)

    bad_expression = {
        "Dimensions": {
            "Key": "REGION",
            "Values": ["us-east-1"],
            "MatchOptions": ["EQUALS", "STARTS_WITH"],
        }
    }
    error = _error(lambda: freetier.get_free_tier_usage(filter=bad_expression))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == "[Message = Exactly one match option must be provided]", error

    # effect absent + control: the single-MatchOption request is unaffected by the rejected one
    after = freetier.get_free_tier_usage(maxResults=1000, filter=good_expression)
    assert len(after.get("freeTierUsages", [])) == len(before.get("freeTierUsages", []))


def _error(fn):
    """Call fn(); return its ClientError's Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
