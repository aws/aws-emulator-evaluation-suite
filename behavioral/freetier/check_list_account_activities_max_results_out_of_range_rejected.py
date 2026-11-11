"""list-account-activities-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-activities-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAccountActivities with maxResults 1001 (past the documented 1000 maximum, which botocore does not check)
    fails with ValidationException and the exact range message, while an in-range value is accepted."""
    freetier = ctx.client("freetier")

    error = _client_error(lambda: freetier.list_account_activities(maxResults=1001))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    ), error["Message"]

    # Positive control: the same call with a valid, in-range maxResults succeeds.
    freetier.list_account_activities(maxResults=1)


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("expected ListAccountActivities to reject maxResults=1001")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

