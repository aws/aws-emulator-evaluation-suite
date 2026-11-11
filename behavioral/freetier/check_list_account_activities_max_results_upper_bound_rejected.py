"""list-account-activities-max-results-upper-bound-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-activities-max-results-upper-bound-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """maxResults one above the service's real upper bound (100 -- the api-models-aws shape
    documents a range of 1-1000, but the live service rejects above 100) is rejected with
    ValidationException, while the boundary value itself is accepted."""
    freetier = ctx.client("freetier")

    error = _client_error(lambda: freetier.list_account_activities(maxResults=101))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), error["Message"]

    # Positive control: the real boundary value is in range and succeeds, proving the rejection
    # above is specific to crossing that boundary rather than every large value.
    freetier.list_account_activities(maxResults=100)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected ListAccountActivities to reject maxResults=101, got {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
