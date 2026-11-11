"""list-pull-time-exclusions-invalid-parameter-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-pull-time-exclusions-invalid-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPullTimeUpdateExclusions with an undecodable nextToken is refused
    InvalidParameterException with the exact message, while a plain call succeeds."""
    ecr = ctx.client("ecr")

    # Positive control first: a plain, parameter-less call succeeds.
    baseline = ecr.list_pull_time_update_exclusions()
    assert "pullTimeUpdateExclusions" in baseline, (
        f"expected a pullTimeUpdateExclusions key on the unfiltered baseline call, "
        f"got {baseline!r}"
    )

    code, message = _error(
        lambda: ecr.list_pull_time_update_exclusions(
            nextToken="not-a-real-continuation-token!!"
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed nextToken, got {code!r}"
    )
    assert message == (
        "Invalid parameter at 'NextToken' failed to satisfy constraint: 'Invalid next token provided'"
    ), message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
