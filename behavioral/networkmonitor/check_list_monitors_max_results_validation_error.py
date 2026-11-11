"""list-monitors-max-results-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-monitors-max-results-validation-error"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMonitors rejects a maxResults outside the modeled 1-25 range with ValidationException and
    the exact message, while maxResults=25 is accepted."""
    nm = ctx.client("networkmonitor")

    err = _error(lambda: nm.list_monitors(maxResults=1000))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = "1 validation error detected: Value '1000' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 25"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # positive control: a maxResults value at the 25-item boundary is accepted
    ok = nm.list_monitors(maxResults=25)
    assert "monitors" in ok, f"expected a well-formed ListMonitors response, got {ok!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
