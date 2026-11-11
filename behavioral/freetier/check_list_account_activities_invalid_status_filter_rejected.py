"""list-account-activities-invalid-status-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-activities-invalid-status-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]

_EXPECTED_MESSAGE = (
    "1 validation error detected: Value '[BOGUS_STATUS]' at 'filterActivityStatuses' failed to "
    "satisfy constraint: Member must satisfy constraint: "
    "[Member must satisfy enum value set: [IN_PROGRESS, COMPLETED, NOT_STARTED, EXPIRING]]"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unknown ActivityStatus filter value is rejected; a valid filter keeps working either side."""
    freetier = ctx.client("freetier")

    before = freetier.list_account_activities(filterActivityStatuses=["COMPLETED"])
    before_ids = sorted(a["activityId"] for a in before.get("activities", []))

    error = _client_error(
        lambda: freetier.list_account_activities(filterActivityStatuses=["BOGUS_STATUS"])
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == _EXPECTED_MESSAGE, error["Message"]

    # effect absent + control: the valid filter still returns exactly the same set as before
    after = freetier.list_account_activities(filterActivityStatuses=["COMPLETED"])
    after_ids = sorted(a["activityId"] for a in after.get("activities", []))
    assert after_ids == before_ids, f"expected {before_ids}, got {after_ids}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
