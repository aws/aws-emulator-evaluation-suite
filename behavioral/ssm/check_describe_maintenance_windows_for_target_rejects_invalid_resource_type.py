"""describe-maintenance-windows-for-target-rejects-invalid-resource-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-maintenance-windows-for-target-rejects-invalid-resource-type"
GROUP = "validation"
SERVICES = ["ssm"]


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeMaintenanceWindowsForTarget rejects a ResourceType outside its modeled enum, while
    the neighbouring valid ResourceType for the same Targets filter succeeds."""
    ssm = ctx.client("ssm")
    targets = [{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}]

    control = ssm.describe_maintenance_windows_for_target(
        Targets=targets, ResourceType="INSTANCE"
    )
    assert control["WindowIdentities"] == [], control

    code, message = _error_code(
        lambda: ssm.describe_maintenance_windows_for_target(
            Targets=targets, ResourceType="NOT_A_RESOURCE_TYPE"
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value at 'resourceType' failed to satisfy constraint: "
        "Member must satisfy enum value set: [RESOURCE_GROUP, INSTANCE]"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
