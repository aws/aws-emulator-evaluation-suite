"""get-managed-resource-malformed-identifier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-managed-resource-malformed-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetManagedResource with a resourceIdentifier that is not ARN-shaped fails AccessDeniedException
    with an empty message, while ListManagedResources succeeds."""
    arc = ctx.client("arc-zonal-shift")

    code, message = _error_detail(
        lambda: arc.get_managed_resource(resourceIdentifier="this-is-not-an-arn-at-all")
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got CODE={code!r}"
    # Real AWS sends this AccessDeniedException with an empty message.
    assert message == "", f"expected an empty AccessDeniedException message, got {message!r}"

    # Positive control: the API itself is healthy for this account/region.
    resp = arc.list_managed_resources()
    assert "items" in resp, f"list_managed_resources returned no 'items' key: {resp!r}"


def _error_detail(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
