"""get-account-activity-not-found-for-unknown-id."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-activity-not-found-for-unknown-id"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountActivity on a well-formed activityId that ListAccountActivities does not list fails with
    ResourceNotFoundException "Activity not found"."""
    freetier = ctx.client("freetier")

    known_ids = {
        a["activityId"]
        for a in freetier.list_account_activities(maxResults=50).get("activities", [])
    }

    unknown_id = (
        uuid.uuid4().hex
    )  # 32 lowercase-hex chars: satisfies length=32, pattern [a-zA-Z0-9]+
    assert unknown_id not in known_ids, (
        f"random id collided with a real activity: {unknown_id}"
    )

    error = _error(lambda: freetier.get_account_activity(activityId=unknown_id))
    assert error["Code"] == "ResourceNotFoundException", error
    assert error["Message"] == "Activity not found", error

    # positive control: the endpoint itself is still healthy for a well-formed request, so the
    # rejection above is specific to this id and not blanket unavailability.
    freetier.list_account_activities(maxResults=1)


def _error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        "get_account_activity unexpectedly succeeded for an unknown id"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
