"""restore-testing-selection-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "restore-testing-selection-empty-vs-absent-preserved"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRestoreTestingSelection returns RestoreMetadataOverrides as written: an empty map stays
    empty and a populated map keeps every key and value, so neither is collapsed into the other
    or dropped."""
    backup = ctx.client("backup")
    sts = ctx.client("sts")

    plan_name = ctx.unique_name("sim2real_rtsel_plan_").replace("-", "_")
    backup.create_restore_testing_plan(
        RestoreTestingPlan={
            "RestoreTestingPlanName": plan_name,
            "RecoveryPointSelection": {
                "Algorithm": "LATEST_WITHIN_WINDOW",
                "RecoveryPointTypes": ["SNAPSHOT"],
                "IncludeVaults": ["*"],
            },
            "ScheduleExpression": "cron(0 5 ? * * *)",
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_rtsel_"},
    )
    ctx.on_cleanup(lambda: backup.delete_restore_testing_plan(RestoreTestingPlanName=plan_name))

    account_id = sts.get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-restore-role"

    empty_name = "empty_overrides"
    populated_name = "populated_overrides"
    overrides = {"encryptionType": "AES256"}

    backup.create_restore_testing_selection(
        RestoreTestingPlanName=plan_name,
        RestoreTestingSelection={
            "RestoreTestingSelectionName": empty_name,
            "ProtectedResourceType": "DynamoDB",
            "ProtectedResourceArns": ["*"],
            "IamRoleArn": role_arn,
            "RestoreMetadataOverrides": {},
        },
    )
    ctx.on_cleanup(
        lambda: backup.delete_restore_testing_selection(
            RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=empty_name
        )
    )

    backup.create_restore_testing_selection(
        RestoreTestingPlanName=plan_name,
        RestoreTestingSelection={
            "RestoreTestingSelectionName": populated_name,
            "ProtectedResourceType": "DynamoDB",
            "ProtectedResourceArns": ["*"],
            "IamRoleArn": role_arn,
            "RestoreMetadataOverrides": overrides,
        },
    )
    ctx.on_cleanup(
        lambda: backup.delete_restore_testing_selection(
            RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=populated_name
        )
    )

    got_empty = backup.get_restore_testing_selection(
        RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=empty_name
    )["RestoreTestingSelection"]
    got_populated = backup.get_restore_testing_selection(
        RestoreTestingPlanName=plan_name, RestoreTestingSelectionName=populated_name
    )["RestoreTestingSelection"]

    assert "RestoreMetadataOverrides" in got_empty, (
        "explicitly empty RestoreMetadataOverrides was dropped entirely (key absent) "
        f"instead of preserved as an empty map: {got_empty!r}"
    )
    assert got_empty["RestoreMetadataOverrides"] == {}, (
        "explicitly empty RestoreMetadataOverrides was not preserved as empty: "
        f"{got_empty['RestoreMetadataOverrides']!r}"
    )

    assert got_populated["RestoreMetadataOverrides"] == overrides, (
        "populated RestoreMetadataOverrides was not preserved verbatim: "
        f"got {got_populated['RestoreMetadataOverrides']!r}, expected {overrides!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
