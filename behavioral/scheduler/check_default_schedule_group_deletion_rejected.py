"""default-schedule-group-deletion-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-schedule-group-deletion-rejected"
GROUP = "e2e"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The built-in 'default' schedule group can never be deleted, unlike an ordinary group."""
    scheduler = ctx.client("scheduler")

    code, message = _error(lambda: scheduler.delete_schedule_group(Name="default"))
    assert code == "ValidationException", f"unexpected code: {code!r}"
    assert message == _DEFAULT_GROUP_REFUSAL, f"unexpected message: {message!r}"

    # Effect absent: the default group is still there and still ACTIVE.
    still_there = scheduler.get_schedule_group(Name="default")
    assert still_there["State"] == "ACTIVE", f"default group left in state {still_there.get('State')!r}"

    # A mutation on the (never-deleted) default group is still rejected the same way.
    code_again, message_again = _error(lambda: scheduler.delete_schedule_group(Name="default"))
    assert code_again == "ValidationException", f"unexpected code on retry: {code_again!r}"
    assert message_again == _DEFAULT_GROUP_REFUSAL, f"unexpected message on retry: {message_again!r}"

    # Positive control in the same file: an ordinary, empty group *can* be deleted.
    group_name = ctx.unique_name("sim2real-sched-grp-")
    scheduler.create_schedule_group(
        Name=group_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: _safe_delete_group(scheduler, group_name))
    created = scheduler.get_schedule_group(Name=group_name)
    assert created["State"] == "ACTIVE", f"newly-created group in state {created.get('State')!r}"

    scheduler.delete_schedule_group(Name=group_name)

    removed = _poll_until_removed(scheduler, group_name, timeout_s=60)
    assert removed, "an ordinary, empty schedule group was never removed after DeleteScheduleGroup"

    # Delete proves gone and unusable: a further mutation on the dead group also fails.
    code_dead, message_dead = _error(lambda: scheduler.delete_schedule_group(Name=group_name))
    assert code_dead == "ResourceNotFoundException", (
        f"deleting an already-deleted group returned {code_dead!r}, not ResourceNotFoundException"
    )
    assert message_dead == f"Schedule group {group_name} does not exist.", (
        f"deleting an already-deleted group returned message {message_dead!r}"
    )


_DEFAULT_GROUP_REFUSAL = "This operation cannot be performed on schedule group default."


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because acceptance where
    real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_group(scheduler, name):
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_removed(scheduler, group_name, timeout_s):
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = scheduler.get_schedule_group(Name=group_name)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        if state != "DELETING":
            raise AssertionError(f"unexpected group state while awaiting removal: {state!r}")
        time.sleep(3)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
