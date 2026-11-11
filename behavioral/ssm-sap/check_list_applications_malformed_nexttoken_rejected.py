"""list-applications-malformed-nexttoken-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-applications-malformed-nexttoken-rejected"
GROUP = "validation"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApplications with a NextToken that does not match the service's
    opaque-token pattern (16-2048 chars) is rejected with ValidationException,
    while a call with no NextToken succeeds."""
    client = ctx.client("ssm-sap")

    err = _error(lambda: client.list_applications(NextToken="short"))
    assert err["Code"] == "ValidationException", err
    expected = (
        "1 validation error detected: Value 'short' at 'nextToken' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: .{16,2048}"
    )
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # positive control: an unpaginated call succeeds
    resp = client.list_applications(MaxResults=5)
    assert "Applications" in resp, f"expected an Applications key, got keys {sorted(resp)}"


def _error(fn):
    """Call fn(); return its botocore error dict (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
