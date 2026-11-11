"""list-endpoints-invalid-next-token-format-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-endpoints-invalid-next-token-format-validation-error"
GROUP = "validation"
SERVICES = ["s3outposts"]

VALIDATION_PREFIX = "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: "
NEXT_TOKEN_PATTERN = r"^[A-Za-z0-9\+\:\/\=\?\#-_]+$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEndpoints rejects a NextToken containing characters outside the documented token
    alphabet with ValidationException, while an ordinary call with no token succeeds."""
    s3o = ctx.client("s3outposts")

    bad_code, bad_message = _error(lambda: s3o.list_endpoints(NextToken="bad token!"))
    assert bad_code == "ValidationException", (
        f"ListEndpoints with a malformed NextToken was refused with {bad_code!r}, "
        f"not ValidationException"
    )
    expected = VALIDATION_PREFIX.format("bad token!", "nextToken") + (
        "Member must satisfy regular expression pattern: " + NEXT_TOKEN_PATTERN
    )
    assert bad_message == expected, f"message={bad_message!r}"

    # Positive control: the same operation with no NextToken at all must succeed, proving the
    # backend isn't unconditionally rejecting ListEndpoints calls.
    resp = s3o.list_endpoints()
    assert "Endpoints" in resp, f"ListEndpoints with no NextToken returned {resp!r}, no Endpoints key"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
