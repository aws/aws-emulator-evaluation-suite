"""list-approval-teams-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-approval-teams-max-results-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["mpa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApprovalTeams refuses MaxResults 0 and 21 (outside the documented 1-20) with
    ValidationException, while a value inside the range succeeds.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    raw = ctx.client("mpa", region="us-east-1", config=Config(parameter_validation=False))

    err_high = _error(lambda: mpa.list_approval_teams(MaxResults=21))
    assert err_high == (
        "ValidationException",
        "1 validation error detected: Value '21' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 20",
    ), err_high

    err_zero = _error(lambda: raw.list_approval_teams(MaxResults=0))
    assert err_zero == (
        "ValidationException",
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1",
    ), err_zero

    resp = mpa.list_approval_teams(MaxResults=20)
    assert "ApprovalTeams" in resp


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
