"""permission-version-lifecycle-and-default-propagation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permission-version-lifecycle-and-default-propagation"
GROUP = "permission-lifecycle"
SERVICES = ["ram"]


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
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_replace_work(ram, work_id: str, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        work = ram.list_replace_permission_associations_work(workIds=[work_id])[
            "replacePermissionAssociationsWorks"
        ][0]
        last = work["status"]
        if last in ("COMPLETED", "FAILED"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"replace-permission-associations work never finished, last status {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A permission's own default version moves on SetDefaultPermissionVersion, but a
    resource share already carrying the old version keeps it until
    ReplacePermissionAssociations explicitly migrates that association."""
    ram = ctx.client("ram")

    name = ctx.unique_name("sim2real-ram-propagate-")
    v1_policy = json.dumps({"Effect": "Allow", "Action": ["codebuild:BatchGetProjects"]})
    created = ram.create_permission(
        name=name, resourceType="codebuild:Project", policyTemplate=v1_policy,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["permission"]
    perm_arn = created["arn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_permission(permissionArn=perm_arn), "UnknownResourceException")
    )

    share_name = ctx.unique_name("sim2real-ram-propagate-share-")
    share = ram.create_resource_share(
        name=share_name, permissionArns=[perm_arn], tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    attached = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
    assert len(attached) == 1 and attached[0]["version"] == "1", (
        f"expected version 1 attached at creation, got {attached!r}"
    )

    v2_policy = json.dumps(
        {"Effect": "Allow", "Action": ["codebuild:BatchGetProjects", "codebuild:ListBuildsForProject"]}
    )
    v2 = ram.create_permission_version(permissionArn=perm_arn, policyTemplate=v2_policy)["permission"]
    assert v2["version"] == "2", f"expected version 2, got {v2['version']!r}"

    versions = {v["version"] for v in ram.list_permission_versions(permissionArn=perm_arn)["permissions"]}
    assert versions == {"1", "2"}, f"expected versions {{1, 2}}, got {versions!r}"

    got_before = ram.get_permission(permissionArn=perm_arn)["permission"]
    assert got_before["version"] == "2" and got_before["defaultVersion"] is True, (
        f"expected the permission's own default to already be version 2, got {got_before!r}"
    )

    # Setting the default version does NOT retroactively move a share that is
    # already attached to the old version.
    not_yet_moved = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
    assert len(not_yet_moved) == 1 and not_yet_moved[0]["version"] == "1", (
        f"expected the share to still carry version 1 before an explicit migration, got {not_yet_moved!r}"
    )
    assert not_yet_moved[0]["defaultVersion"] is False, (
        f"expected version 1 to no longer be marked default, got {not_yet_moved[0]!r}"
    )

    # Deleting the now-non-default version 1 while it is still attached to the share
    # is refused; the attachment must be moved first.
    code, message = _error(
        lambda: ram.delete_permission_version(permissionArn=perm_arn, permissionVersion=1)
    )
    assert code == "OperationNotPermittedException", (
        f"expected OperationNotPermittedException, got {code}: {message!r}"
    )
    assert message == (
        "The customer-managed permission version is associated to resource shares. "
        "Remove all associations of this permission version and try again."
    ), f"unexpected message {message!r}"

    work = ram.replace_permission_associations(
        fromPermissionArn=perm_arn, fromPermissionVersion=1, toPermissionArn=perm_arn
    )["replacePermissionAssociationsWork"]
    status = _wait_replace_work(ram, work["id"])
    assert status == "COMPLETED", f"expected the migration work to COMPLETE, got {status!r}"

    moved = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
    assert len(moved) == 1 and moved[0]["version"] == "2", (
        f"expected the share to carry version 2 after the migration, got {moved!r}"
    )
    assert moved[0]["defaultVersion"] is True, f"expected version 2 to be default, got {moved[0]!r}"

    # Now that no share holds version 1, deleting it succeeds; ListPermissionVersions
    # keeps the entry for audit but marks it DELETED, and version 2 is unaffected.
    ram.delete_permission_version(permissionArn=perm_arn, permissionVersion=1)
    statuses = {
        v["version"]: v["status"]
        for v in ram.list_permission_versions(permissionArn=perm_arn)["permissions"]
    }
    assert statuses == {"1": "DELETED", "2": "ATTACHABLE"}, (
        f"expected version 1 DELETED and version 2 ATTACHABLE, got {statuses!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
