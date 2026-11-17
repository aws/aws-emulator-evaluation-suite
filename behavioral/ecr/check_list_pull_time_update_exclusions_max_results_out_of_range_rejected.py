"""list-pull-time-update-exclusions-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "list-pull-time-update-exclusions-max-results-out-of-range-rejected"
GROUP = 'registry-config'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPullTimeUpdateExclusions with maxResults above 1000 is rejected with
    InvalidParameterException; the same call at the 1000 boundary succeeds."""
    ecr = ctx.client("ecr")

    ok = ecr.list_pull_time_update_exclusions(maxResults=1000)
    assert "pullTimeUpdateExclusions" in ok, f"expected a listing at the maxResults boundary, got {ok}"

    expected = (
        "Invalid parameter at 'maxResults' failed to satisfy constraint: 'Member must have "
        "value less than or equal to 1000'"
    )
    code, message = _error(lambda: ecr.list_pull_time_update_exclusions(maxResults=1001))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
