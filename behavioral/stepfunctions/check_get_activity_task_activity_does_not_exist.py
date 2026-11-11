"""get-activity-task-activity-does-not-exist."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-activity-task-activity-does-not-exist"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ActivityDoesNotExist, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetActivityTask against an activity ARN that has already been deleted
    must fail ActivityDoesNotExist — never silently long-poll (or return an
    empty taskToken) against a resource that no longer exists.
    """
    sfn = ctx.client("stepfunctions")
    activity_arn = sfn.create_activity(name=ctx.unique_name("sim2real-behav-act-"))["activityArn"]
    sfn.delete_activity(activityArn=activity_arn)

    code, message = _error_code(lambda: sfn.get_activity_task(activityArn=activity_arn))
    assert code == "ActivityDoesNotExist", f"expected ActivityDoesNotExist, got {code}"
    expected_message = f"Activity Does Not Exist: '{activity_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
