"""list-app-monitors-max-results-over-100-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-app-monitors-max-results-over-100-rejected"
GROUP = "listing"
SERVICES = ["rum"]

_OVER_LIMIT = (
    "ValidationException",
    "1 validation error detected: Value '101' at 'maxResults' failed to satisfy "
    "constraint: Member must have value less than or equal to 100",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    actual_code, actual_message = _error(fn)
    assert actual_code == code, f"got code {actual_code!r}, expected {code!r}"
    assert actual_message == message, f"got message {actual_message!r}, expected {message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAppMonitors accepts MaxResults up to 100 and rejects 101 with its exact message.
    """
    r = ctx.client("rum")

    at_limit = r.list_app_monitors(MaxResults=100)
    assert "AppMonitorSummaries" in at_limit, (
        f"MaxResults=100 did not return AppMonitorSummaries: {at_limit!r}"
    )

    expect_error(lambda: r.list_app_monitors(MaxResults=101), *_OVER_LIMIT)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
