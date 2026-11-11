"""framework-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "framework-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A framework: create -> describe -> update (controls reflected) -> delete -> subsequent describe raises
    ResourceNotFoundException."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_fw_").replace("-", "_")

    backup.create_framework(
        FrameworkName=name,
        FrameworkDescription="sim2real behavioral fidelity check framework",
        FrameworkControls=[
            {
                "ControlName": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN",
                "ControlScope": {
                    "ComplianceResourceTypes": ["RDS"],
                    "Tags": {"sim2real-framework-lifecycle": name},
                },
            }
        ],
        FrameworkTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_fw"},
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            backup.delete_framework(FrameworkName=name)

    ctx.on_cleanup(_cleanup)

    # DeploymentStatus (not FrameworkStatus, which reports Config-recording coverage:
    # ACTIVE|PARTIALLY_ACTIVE|INACTIVE|UNAVAILABLE) carries the create/update lifecycle:
    # CREATE_IN_PROGRESS|UPDATE_IN_PROGRESS|DELETE_IN_PROGRESS|COMPLETED|FAILED.
    described = _poll_until(
        lambda: backup.describe_framework(FrameworkName=name),
        lambda r: r["DeploymentStatus"] not in ("CREATE_IN_PROGRESS",),
        timeout_s=120.0,
    )
    control_name = described["FrameworkControls"][0]["ControlName"]
    assert control_name == "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN", (
        f"expected control BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN, got {control_name!r}"
    )
    resource_types = described["FrameworkControls"][0]["ControlScope"]["ComplianceResourceTypes"]
    assert resource_types == ["RDS"], f"expected ComplianceResourceTypes ['RDS'], got {resource_types!r}"

    listed = backup.list_frameworks()["Frameworks"]
    assert any(f["FrameworkName"] == name for f in listed), (
        f"expected {name!r} in list_frameworks() after create, got names={[f['FrameworkName'] for f in listed]!r}"
    )

    _update_framework_with_retry(
        backup,
        name,
        FrameworkControls=[
            {
                "ControlName": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN",
                "ControlScope": {"ComplianceResourceTypes": ["DynamoDB"]},
            }
        ],
    )
    updated = _poll_until(
        lambda: backup.describe_framework(FrameworkName=name),
        lambda r: r["DeploymentStatus"] not in ("UPDATE_IN_PROGRESS",),
        timeout_s=120.0,
    )
    updated_resource_types = updated["FrameworkControls"][0]["ControlScope"]["ComplianceResourceTypes"]
    assert updated_resource_types == ["DynamoDB"], (
        f"expected ComplianceResourceTypes ['DynamoDB'] after update, got {updated_resource_types!r}"
    )

    _delete_framework_with_retry(backup, name)
    deleted["done"] = True

    code, message = _error(lambda: backup.describe_framework(FrameworkName=name), timeout_s=60.0)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected_message = f"Framework {name} not found in account {ctx.account}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_after_delete_code, update_after_delete_message = _error(
        lambda: backup.update_framework(
            FrameworkName=name,
            FrameworkControls=[{"ControlName": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"}],
        )
    )
    assert update_after_delete_code == "ResourceNotFoundException", (
        f"expected UpdateFramework on a deleted framework to fail with ResourceNotFoundException, "
        f"got {update_after_delete_code!r}"
    )
    expected_update_after_delete_message = f"Framework {name} not found in account {ctx.account}."
    assert update_after_delete_message == expected_update_after_delete_message, f"expected message {expected_update_after_delete_message!r}, got {update_after_delete_message!r}"

    listed_after = backup.list_frameworks()["Frameworks"]
    assert not any(f["FrameworkName"] == name for f in listed_after), (
        f"expected {name!r} absent from list_frameworks() after delete, "
        f"got names={[f['FrameworkName'] for f in listed_after]!r}"
    )


def _update_framework_with_retry(backup, name, retries=8, delay=10.0, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(retries):
        try:
            backup.update_framework(FrameworkName=name, **kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            last_exc = exc
            time.sleep(delay)
    raise last_exc


def _delete_framework_with_retry(backup, name, retries=8, delay=10.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(retries):
        try:
            backup.delete_framework(FrameworkName=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            last_exc = exc
            time.sleep(delay)
    raise last_exc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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
