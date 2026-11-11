"""create-restore-testing-plan-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-restore-testing-plan-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a restore testing plan with an existing name fails with AlreadyExistsException and
    leaves the original unchanged; after deleting it, the name is reusable with the new
    definition."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_rtp_dup_").replace("-", "_")

    original_schedule = "cron(0 5 ? * * *)"
    duplicate_schedule = "cron(0 8 ? * * *)"

    def _create_conflicting():
        return backup.create_restore_testing_plan(
            RestoreTestingPlan={
                "RestoreTestingPlanName": name,
                "RecoveryPointSelection": {
                    "Algorithm": "RANDOM_WITHIN_WINDOW",
                    "RecoveryPointTypes": ["CONTINUOUS"],
                    "IncludeVaults": ["*"],
                },
                "ScheduleExpression": duplicate_schedule,
            }
        )

    backup.create_restore_testing_plan(
        RestoreTestingPlan={
            "RestoreTestingPlanName": name,
            "RecoveryPointSelection": {
                "Algorithm": "LATEST_WITHIN_WINDOW",
                "RecoveryPointTypes": ["SNAPSHOT"],
                "IncludeVaults": ["*"],
            },
            "ScheduleExpression": original_schedule,
        }
    )
    deleted = {"done": False}

    def _cleanup_original():
        if not deleted["done"]:
            backup.delete_restore_testing_plan(RestoreTestingPlanName=name)

    ctx.on_cleanup(_cleanup_original)

    code, message = _error(_create_conflicting)
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    assert message == (
        f"Restore testing plan [{name}] already exists in account [{ctx.account}]."
    ), f"actual_message={message!r}"

    unchanged = backup.get_restore_testing_plan(RestoreTestingPlanName=name)
    assert unchanged["RestoreTestingPlan"]["ScheduleExpression"] == original_schedule, (
        "duplicate-name create mutated the original plan's schedule"
    )
    assert unchanged["RestoreTestingPlan"]["RecoveryPointSelection"]["Algorithm"] == "LATEST_WITHIN_WINDOW", (
        "duplicate-name create mutated the original plan's RecoveryPointSelection.Algorithm: "
        f"got {unchanged['RestoreTestingPlan']['RecoveryPointSelection']['Algorithm']!r}"
    )

    # Restore leg: delete the original, then the identical conflicting call must now
    # succeed and adopt its own definition -- the name was rejected for conflicting,
    # not for some latent validation defect in the duplicate's own parameters.
    backup.delete_restore_testing_plan(RestoreTestingPlanName=name)
    deleted["done"] = True

    _create_conflicting()
    ctx.on_cleanup(lambda: backup.delete_restore_testing_plan(RestoreTestingPlanName=name))

    reused = backup.get_restore_testing_plan(RestoreTestingPlanName=name)["RestoreTestingPlan"]
    assert reused["ScheduleExpression"] == duplicate_schedule, (
        f"reused name did not adopt the freed plan's schedule: got {reused['ScheduleExpression']!r}"
    )
    assert reused["RecoveryPointSelection"]["Algorithm"] == "RANDOM_WITHIN_WINDOW", (
        f"reused name did not adopt the freed plan's Algorithm: got {reused['RecoveryPointSelection']['Algorithm']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected AlreadyExistsException, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
