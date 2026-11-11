"""list-regions-malformed-next-token-validation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-regions-malformed-next-token-validation"
GROUP = "error-semantics"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRegions with MaxResults above 25 fails with ValidationException and the exact range message,
    and a malformed NextToken is ignored: the call returns a non-empty first page.
    """
    wsi = ctx.client("workspaces-instances")

    code, message = _error(lambda: wsi.list_regions(MaxResults=999))
    assert code == "ValidationException", (code, message)
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 25"
    ), message

    # positive control: an in-range MaxResults succeeds and returns real regions
    baseline = wsi.list_regions(MaxResults=5)
    assert len(baseline["Regions"]) > 0, "positive control: expected at least one region"

    # malformed NextToken is silently ignored, not validated -- assert that contract directly
    garbage = wsi.list_regions(NextToken="not-a-real-token-###garbage###")
    assert len(garbage["Regions"]) > 0, (
        f"expected a malformed NextToken to be ignored and return a normal first page, "
        f"got {len(garbage['Regions'])} regions"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
