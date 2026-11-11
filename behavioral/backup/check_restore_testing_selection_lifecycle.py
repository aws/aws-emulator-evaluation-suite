"""restore-testing-selection-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "restore-testing-selection-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A restore testing selection: create -> update -> delete -> Get raises ResourceNotFoundException, and it
    disappears from ListRestoreTestingSelections."""
    backup = ctx.client("backup")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    plan_name = ctx.unique_name("sim2real_rtp_sel_").replace("-", "_")
    selection_name = ctx.unique_name("sim2real_sel_").replace("-", "_")
    role_arn_1 = f"arn:aws:iam::{account_id}:role/sim2real-restore-testing-role-a"
    role_arn_2 = f"arn:aws:iam::{account_id}:role/sim2real-restore-testing-role-b"

    backup.create_restore_testing_plan(
        RestoreTestingPlan={
            "RestoreTestingPlanName": plan_name,
            "ScheduleExpression": "cron(0 5 ? * * *)",
            "RecoveryPointSelection": {
                "Algorithm": "LATEST_WITHIN_WINDOW",
                "RecoveryPointTypes": ["SNAPSHOT"],
                "IncludeVaults": ["*"],
            },
        }
    )
    ctx.on_cleanup(lambda: backup.delete_restore_testing_plan(RestoreTestingPlanName=plan_name))

    backup.create_restore_testing_selection(
        RestoreTestingPlanName=plan_name,
        RestoreTestingSelection={
            "RestoreTestingSelectionName": selection_name,
            "ProtectedResourceType": "DynamoDB",
            "ProtectedResourceArns": ["*"],
            "IamRoleArn": role_arn_1,
        },
    )
    deleted = {"done": False}

    def _cleanup_selection():
        if not deleted["done"]:
            backup.delete_restore_testing_selection(
                RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=selection_name
            )

    ctx.on_cleanup(_cleanup_selection)

    got = backup.get_restore_testing_selection(
        RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=selection_name
    )["RestoreTestingSelection"]
    assert got["IamRoleArn"] == role_arn_1, f"expected IamRoleArn {role_arn_1!r}, got {got['IamRoleArn']!r}"

    listed = backup.list_restore_testing_selections(RestoreTestingPlanName=plan_name)["RestoreTestingSelections"]
    assert any(s["RestoreTestingSelectionName"] == selection_name for s in listed), (
        f"{selection_name!r} missing from ListRestoreTestingSelections: {listed!r}"
    )

    backup.update_restore_testing_selection(
        RestoreTestingPlanName=plan_name,
        RestoreTestingSelectionName=selection_name,
        RestoreTestingSelection={
            "ProtectedResourceArns": ["*"],
            "IamRoleArn": role_arn_2,
        },
    )

    updated = backup.get_restore_testing_selection(
        RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=selection_name
    )["RestoreTestingSelection"]
    assert updated["IamRoleArn"] == role_arn_2, (
        f"expected updated IamRoleArn {role_arn_2!r}, got {updated['IamRoleArn']!r}"
    )

    backup.delete_restore_testing_selection(
        RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=selection_name
    )
    deleted["done"] = True

    code, message = _error(
        lambda: backup.get_restore_testing_selection(
            RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=selection_name
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = "Restore testing selection does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed_after = backup.list_restore_testing_selections(RestoreTestingPlanName=plan_name)[
        "RestoreTestingSelections"
    ]
    assert not any(s["RestoreTestingSelectionName"] == selection_name for s in listed_after), (
        f"deleted selection {selection_name!r} still present in ListRestoreTestingSelections: {listed_after!r}"
    )

    mutate_code, mutate_message = _error(
        lambda: backup.update_restore_testing_selection(
            RestoreTestingPlanName=plan_name,
            RestoreTestingSelectionName=selection_name,
            RestoreTestingSelection={
                "ProtectedResourceArns": ["*"],
                "IamRoleArn": role_arn_2,
            },
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted selection to fail with ResourceNotFoundException, got {mutate_code!r}"
    )
    expected_mutate_message = "Restore testing selection does not exist."
    assert mutate_message == expected_mutate_message, f"expected message {expected_mutate_message!r}, got {mutate_message!r}"


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
