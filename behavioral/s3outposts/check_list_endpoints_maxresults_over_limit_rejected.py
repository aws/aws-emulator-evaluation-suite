"""list-endpoints-maxresults-over-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-endpoints-maxresults-over-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3outposts"]

MAX_RESULTS_MESSAGE = (
    "1 validation error detected: Value '1000' at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 100"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEndpoints rejects a MaxResults value above the documented 0-100 range with
    ValidationException instead of silently clamping it and returning a page anyway; the
    identical call with MaxResults at the upper boundary (100) is accepted."""
    s3o = ctx.client("s3outposts")

    bad_code, bad_message = _error(lambda: s3o.list_endpoints(MaxResults=1000))
    assert bad_code == "ValidationException", f"got={bad_code!r}"
    assert bad_message == MAX_RESULTS_MESSAGE, f"message={bad_message!r}"

    # Positive control: the boundary value itself (100) must be accepted, proving the
    # ValidationException above was specifically about exceeding the allowed range and not
    # some unrelated request-shape problem.
    resp = s3o.list_endpoints(MaxResults=100)
    assert "Endpoints" in resp, f"boundary MaxResults=100 call did not return a page: {resp!r}"


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

