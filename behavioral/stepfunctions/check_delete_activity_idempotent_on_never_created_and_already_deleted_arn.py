"""delete-activity-idempotent-on-never-created-and-already-deleted-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-activity-idempotent-on-never-created-and-already-deleted-arn"
GROUP = "activities"
SERVICES = ["stepfunctions"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises too, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_gone(sfn, arn, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sfn.describe_activity(activityArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ActivityDoesNotExist":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"activity {arn} did not become not-found within {timeout_s}s")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteActivity returns its empty result on an ARN that was never created, and again on
    one already deleted, while a malformed ARN is rejected with InvalidArn and its message.
    """
    sfn = ctx.client("stepfunctions")

    # Positive control: DeleteActivity really deletes a live activity.
    name = ctx.unique_name("sim2real-behav-act-")
    live_arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=live_arn), "ActivityDoesNotExist"))
    pre = sfn.describe_activity(activityArn=live_arn)
    assert pre["name"] == name, f"expected name {name!r} on the live activity, got {pre['name']!r}"

    delete_resp = sfn.delete_activity(activityArn=live_arn)
    body = {k: v for k, v in delete_resp.items() if not k.startswith("ResponseMetadata")}
    assert body == {}, f"expected an empty result from DeleteActivity, got {body!r}"
    _poll_gone(sfn, live_arn)

    # A well-formed ARN that was never created: DeleteActivity still returns empty -- the model
    # declares no not-found error for this operation.
    never_created_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:activity:"
        f"{ctx.unique_name('sim2real-behav-act-never-')}"
    )
    never_resp = sfn.delete_activity(activityArn=never_created_arn)
    never_body = {k: v for k, v in never_resp.items() if not k.startswith("ResponseMetadata")}
    assert never_body == {}, (
        f"expected an empty result deleting a never-created activity ARN, got {never_body!r}"
    )
    never_err = _error(lambda: sfn.describe_activity(activityArn=never_created_arn))
    assert never_err[0] == "ActivityDoesNotExist", (
        f"expected ActivityDoesNotExist describing the never-created ARN, got {never_err!r}"
    )

    # Repeating DeleteActivity on the now-dead live ARN also returns empty: the operation is
    # idempotent, not merely tolerant of ARNs that never existed.
    again_resp = sfn.delete_activity(activityArn=live_arn)
    again_body = {k: v for k, v in again_resp.items() if not k.startswith("ResponseMetadata")}
    assert again_body == {}, f"expected an empty result on a second delete, got {again_body!r}"

    # A malformed ARN is a distinct input class and is rejected.
    code, message = _error(lambda: sfn.delete_activity(activityArn="not-an-arn"))
    assert code == "InvalidArn", f"expected InvalidArn, got {code!r}"
    expected_message = "Invalid Arn: 'Invalid ARN prefix: not-an-arn'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
