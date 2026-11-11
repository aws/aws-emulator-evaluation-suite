"""delete-filter-twice-returns-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-filter-twice-returns-not-found"
GROUP = "error-semantics"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteFilter is idempotent for an ARN whose lifecycle you own (deleting an already-deleted
    filter of yours succeeds rather than erroring), but a syntactically invalid ARN -- not merely
    "well-formed but nonexistent" -- is still rejected outright."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-doubledel-")

    created = inspector2.create_filter(
        action="NONE",
        name=name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "LOW"}]},
    )
    arn = created["arn"]

    # Positive control: the first delete of a real, existing filter succeeds.
    first_delete = inspector2.delete_filter(arn=arn)
    assert first_delete["arn"] == arn, f"expected first delete to echo {arn}, got {first_delete}"

    # State finding: deleting the very same ARN again is idempotent, not an error.
    second_delete = inspector2.delete_filter(arn=arn)
    assert second_delete["arn"] == arn, f"expected idempotent delete to echo {arn}, got {second_delete}"

    # Effect confirmation: the filter is absent from ListFilters.
    arns = _all_filter_arns(inspector2)
    assert arn not in arns, "filter unexpectedly present in ListFilters after being deleted"

    # Negative: a syntactically invalid ARN (not merely a nonexistent-but-well-formed one) is
    # still rejected outright, not silently treated as a no-op success.
    code, msg = _error_code(lambda: inspector2.delete_filter(arn="not-an-arn-at-all"))
    assert code == "ValidationException", f"code={code!r}"
    assert msg == "Invalid Filter Arn not-an-arn-at-all", msg


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _all_filter_arns(inspector2) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_filters(**kwargs)
        for f in resp.get("filters", []):
            arns.add(f["arn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)



