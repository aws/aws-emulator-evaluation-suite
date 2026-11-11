"""maintenance-window-target-update-and-describe."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-target-update-and-describe"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered target's attributes updated via UpdateMaintenanceWindowTarget are
    reflected in DescribeMaintenanceWindowsForTarget."""
    ssm = ctx.client("ssm")
    window_id = _create_window(ctx)

    registered = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        # RegisterTargetWithMaintenanceWindow rejects the "*" wildcard as an
        # invalid instance id (unlike CreateAssociation's Targets, which
        # accepts it); use a syntactically valid (17-hex-char), if
        # non-existent, instance id -- AWS validates the instance-id format
        # (i- followed by 17 hex characters) even for a node that doesn't
        # exist.
        Targets=[{"Key": "InstanceIds", "Values": ["i-00000000000000001"]}],
        OwnerInformation="initial-owner",
    )
    target_id = registered["WindowTargetId"]
    ctx.on_cleanup(lambda: _deregister_target_if_exists(ssm, window_id, target_id))

    updated_instance = "i-0123456789abcdef0"
    updated = ssm.update_maintenance_window_target(
        WindowId=window_id,
        WindowTargetId=target_id,
        Targets=[{"Key": "InstanceIds", "Values": [updated_instance]}],
        OwnerInformation="updated-owner",
    )
    assert updated["OwnerInformation"] == "updated-owner"
    assert updated["Targets"] == [{"Key": "InstanceIds", "Values": [updated_instance]}]

    matches = ssm.describe_maintenance_windows_for_target(
        Targets=[{"Key": "InstanceIds", "Values": [updated_instance]}],
        ResourceType="INSTANCE",
    )["WindowIdentities"]
    assert window_id in {w["WindowId"] for w in matches}

    # A previously unrelated instance ID must not match the updated target.
    unrelated_instance = "i-0fedcba9876543210"
    non_matches = ssm.describe_maintenance_windows_for_target(
        Targets=[{"Key": "InstanceIds", "Values": [unrelated_instance]}],
        ResourceType="INSTANCE",
    )["WindowIdentities"]
    assert window_id not in {w["WindowId"] for w in non_matches}


def _create_window(ctx) -> str:
    ssm = ctx.client("ssm")
    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0 0 ? * SUN *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
    return window_id


def _deregister_target_if_exists(ssm, window_id: str, target_id: str) -> None:
    try:
        ssm.deregister_target_from_maintenance_window(WindowId=window_id, WindowTargetId=target_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DoesNotExistException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
