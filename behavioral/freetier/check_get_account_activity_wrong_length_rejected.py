"""get-account-activity-wrong-length-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-activity-wrong-length-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountActivity (client-side validation off) with an activityId shorter than 32 characters fails with
    ValidationException and the exact length message, while a 32-character nonexistent id gets
    ResourceNotFoundException "Activity not found"."""
    raw = ctx.client("freetier", config=Config(parameter_validation=False))
    too_short_id = "a" * 20

    error = _error(lambda: raw.get_account_activity(activityId=too_short_id))
    assert error["Code"] == "ValidationException", f"wrong-length activityId got {error}"
    assert error["Message"] == (
        f"1 validation error detected: Value '{too_short_id}' at 'activityId' failed to satisfy "
        "constraint: Member must have length greater than or equal to 32"
    ), error

    # well-formed (32 chars, matches the id pattern) but nonexistent -- proves the
    # ValidationException above is about the malformed length, not a blanket rejection.
    well_formed_missing_id = "a" * 32
    missing = _error(lambda: raw.get_account_activity(activityId=well_formed_missing_id))
    assert missing["Code"] == "ResourceNotFoundException", (
        f"well-formed but nonexistent id got {missing}"
    )
    assert missing["Message"] == "Activity not found", missing


def _error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

