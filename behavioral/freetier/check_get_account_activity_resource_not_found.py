"""get-account-activity-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-activity-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["freetier"]


def _error(fn):
    """Call fn(); return its ClientError's Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountActivity for a well-formed but nonexistent activityId returns ResourceNotFoundException."""
    freetier = ctx.client("freetier")

    known_ids = {
        a["activityId"]
        for a in freetier.list_account_activities(maxResults=50).get("activities", [])
    }
    # Well-formed per the ^[a-zA-Z0-9]{32}$ constraint; confirmed absent from the account's
    # own activity list rather than merely assumed unlikely to collide.
    bogus_id = "f" * 32
    assert bogus_id not in known_ids, f"unexpectedly a real activity id: {bogus_id}"

    error = _error(lambda: freetier.get_account_activity(activityId=bogus_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for nonexistent activityId {bogus_id!r}, got {error}"
    )
    assert error["Message"] == "Activity not found", error

    # positive control: the endpoint itself is still healthy for a well-formed request,
    # so the rejection above is specific to this id and not blanket unavailability.
    freetier.list_account_activities(maxResults=1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
