"""restore-testing-plan-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "restore-testing-plan-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A restore testing plan: create -> update (schedule reflected) -> delete -> Get raises
    ResourceNotFoundException -> a mutation on the dead plan also fails -> gone from the list."""
    backup = ctx.client("backup")
    plan_name = ctx.unique_name("sim2real_rtp_").replace("-", "_")

    backup.create_restore_testing_plan(
        RestoreTestingPlan={
            "RestoreTestingPlanName": plan_name,
            "ScheduleExpression": "cron(0 5 ? * * *)",
            "RecoveryPointSelection": {
                "Algorithm": "LATEST_WITHIN_WINDOW",
                "RecoveryPointTypes": ["SNAPSHOT"],
                "IncludeVaults": ["*"],
                "SelectionWindowDays": 30,
            },
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_rtp"},
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            backup.delete_restore_testing_plan(RestoreTestingPlanName=plan_name)

    ctx.on_cleanup(_cleanup)

    got = backup.get_restore_testing_plan(RestoreTestingPlanName=plan_name)["RestoreTestingPlan"]
    assert got["ScheduleExpression"] == "cron(0 5 ? * * *)", (
        f"expected the just-created schedule, got {got['ScheduleExpression']!r}"
    )

    listed = backup.list_restore_testing_plans()["RestoreTestingPlans"]
    assert any(p["RestoreTestingPlanName"] == plan_name for p in listed), (
        f"{plan_name!r} not present in list_restore_testing_plans: {[p['RestoreTestingPlanName'] for p in listed]!r}"
    )

    backup.update_restore_testing_plan(
        RestoreTestingPlanName=plan_name,
        RestoreTestingPlan={
            "ScheduleExpression": "cron(0 6 ? * * *)",
            "RecoveryPointSelection": {
                "Algorithm": "LATEST_WITHIN_WINDOW",
                "RecoveryPointTypes": ["SNAPSHOT"],
                "IncludeVaults": ["*"],
                "SelectionWindowDays": 45,
            },
        },
    )

    updated = backup.get_restore_testing_plan(RestoreTestingPlanName=plan_name)["RestoreTestingPlan"]
    assert updated["ScheduleExpression"] == "cron(0 6 ? * * *)", (
        f"expected the updated schedule, got {updated['ScheduleExpression']!r}"
    )
    assert updated["RecoveryPointSelection"]["SelectionWindowDays"] == 45, (
        f"expected SelectionWindowDays=45 after update, got {updated['RecoveryPointSelection']['SelectionWindowDays']!r}"
    )

    backup.delete_restore_testing_plan(RestoreTestingPlanName=plan_name)
    deleted["done"] = True

    code, message = _error(lambda: backup.get_restore_testing_plan(RestoreTestingPlanName=plan_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on a deleted plan, got {code!r}"
    expected_message = "Restore testing plan does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: backup.update_restore_testing_plan(
            RestoreTestingPlanName=plan_name,
            RestoreTestingPlan={
                "ScheduleExpression": "cron(0 7 ? * * *)",
                "RecoveryPointSelection": {
                    "Algorithm": "LATEST_WITHIN_WINDOW",
                    "RecoveryPointTypes": ["SNAPSHOT"],
                    "IncludeVaults": ["*"],
                    "SelectionWindowDays": 30,
                },
            },
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted plan to fail with ResourceNotFoundException, got {update_code!r}"
    )
    expected_update_message = "Restore testing plan does not exist."
    assert update_message == expected_update_message, f"expected message {expected_update_message!r}, got {update_message!r}"

    listed_after = backup.list_restore_testing_plans()["RestoreTestingPlans"]
    assert not any(p["RestoreTestingPlanName"] == plan_name for p in listed_after), (
        f"{plan_name!r} still present in list_restore_testing_plans after delete"
    )


def _error(fn, *, timeout_s: float = 0.0, interval_s: float = 3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS once timeout_s has passed raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
