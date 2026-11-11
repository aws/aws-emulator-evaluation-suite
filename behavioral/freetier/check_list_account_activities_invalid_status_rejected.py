"""list-account-activities-invalid-status-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-activities-invalid-status-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]

_EXPECTED_MESSAGE = (
    "1 validation error detected: Value '[BOGUS_STATUS]' at 'filterActivityStatuses' failed to "
    "satisfy constraint: Member must satisfy constraint: "
    "[Member must satisfy enum value set: [IN_PROGRESS, COMPLETED, NOT_STARTED, EXPIRING]]"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An out-of-enum filterActivityStatuses value is rejected with ValidationException, and the
    rejection has no side effect: an independent read with a valid filter, issued right after,
    returns exactly the same activities it returned right before.
    """
    freetier = ctx.client("freetier")

    # Positive control: the account and this exact filter shape are otherwise healthy, so the
    # rejection below can be attributed to the out-of-enum value and not to a target that refuses
    # every filtered call.
    before = freetier.list_account_activities(filterActivityStatuses=["COMPLETED"])
    before_ids = sorted(a["activityId"] for a in before.get("activities", []))

    error = _client_error(
        lambda: freetier.list_account_activities(filterActivityStatuses=["BOGUS_STATUS"])
    )
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == _EXPECTED_MESSAGE, error["Message"]

    # Independent read at the destination: the valid filter still returns the identical set of
    # activities, so the rejected call left nothing behind.
    after = freetier.list_account_activities(filterActivityStatuses=["COMPLETED"])
    after_ids = sorted(a["activityId"] for a in after.get("activities", []))
    assert after_ids == before_ids, (before_ids, after_ids)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"BOGUS_STATUS was accepted and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
