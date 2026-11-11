"""op-contract-update-capacity-manager-monitored-tag-keys."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-update-capacity-manager-monitored-tag-keys"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """UpdateCapacityManagerMonitoredTagKeys, with Capacity Manager enabled, returns the activated tag key
    in CapacityManagerTagKeys with status activating or activated; with DryRun it fails with
    DryRunOperation and the standard message and does not activate the other key."""
    ec2 = ctx.client("ec2")

    was_enabled = _capacity_manager_enabled(ec2)
    try:
        ec2.enable_capacity_manager(OrganizationsAccess=False)
    except ClientError as exc:
        raise AssertionError(f"EnableCapacityManager rejected: {exc.response['Error']['Code']}")
    if not was_enabled:
        ctx.on_cleanup(lambda: ec2.disable_capacity_manager())

    tag_key = ctx.unique_name("sim2real-cm-tag-")
    ctx.on_cleanup(lambda: _best_effort_deactivate(ec2, tag_key))

    resp = ec2.update_capacity_manager_monitored_tag_keys(ActivateTagKeys=[tag_key])
    entries = {item["TagKey"]: item for item in resp["CapacityManagerTagKeys"]}
    assert tag_key in entries, f"activated tag key {tag_key!r} missing from response: {entries}"
    status = entries[tag_key]["Status"]
    assert status in ("activating", "activated"), f"unexpected activation status: {status!r}"

    # Distinct error boundary: DryRun must short-circuit with DryRunOperation and must not
    # activate the second tag key (permission-check-before-mutation contract).
    other_tag_key = ctx.unique_name("sim2real-cm-tag-dryrun-")
    code, message = _error(
        lambda: ec2.update_capacity_manager_monitored_tag_keys(
            ActivateTagKeys=[other_tag_key], DryRun=True
        )
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )

    get_resp = ec2.get_capacity_manager_monitored_tag_keys()
    dry_run_keys = {item["TagKey"] for item in get_resp["CapacityManagerTagKeys"]}
    assert other_tag_key not in dry_run_keys, (
        "DryRun request should not have mutated monitored tag keys"
    )


def _capacity_manager_enabled(ec2) -> bool:
    """Whether Capacity Manager is on here; a never-enabled account refuses the read."""
    try:
        return ec2.get_capacity_manager_attributes()["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CapacityManager.Disabled":
            raise
        return False


def _best_effort_deactivate(ec2, tag_key: str) -> None:
    ec2.update_capacity_manager_monitored_tag_keys(DeactivateTagKeys=[tag_key])


def _error(fn: Callable[[], Any]):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
