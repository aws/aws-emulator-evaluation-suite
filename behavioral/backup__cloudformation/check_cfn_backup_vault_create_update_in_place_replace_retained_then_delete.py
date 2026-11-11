"""cfn-backup-vault-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-backup-vault-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["backup", "cloudformation"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A deleted vault stops resolving within seconds; the bound only stops a hung poll.
_GONE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: DescribeBackupVault of a vault that does not exist.
_NOT_FOUND = (
    "AccessDeniedException",
    "Insufficient privileges to perform this action.",
)
#: Governance-mode locks (no ChangeableForDays), so the check can always remove them.
_LOCK_V1 = {"MinRetentionDays": 1, "MaxRetentionDays": 30}
_LOCK_V2 = {"MinRetentionDays": 2, "MaxRetentionDays": 30}


def _policy(sid: str, action: str) -> dict:
    """A vault access policy denying one recovery-point change; the vault holds no recovery points.

    One action as a string: Backup stores a one-element Action list as its string.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Deny",
                "Principal": "*",
                "Action": action,
                "Resource": "*",
            }
        ],
    }


_POLICY_V1 = _policy("DenyRecoveryPointDelete", "backup:DeleteRecoveryPoint")
_POLICY_V2 = _policy("DenyRecoveryPointLifecycle", "backup:UpdateRecoveryPointLifecycle")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::Backup::BackupVault survives create, in-place update, retained replace and delete.

    Backup reads back the templated access policy and vault lock; changing both keeps the vault; a
    BackupVaultName change under UpdateReplacePolicy Retain keeps the old vault too.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-backupvault.html
    """
    cfn = ctx.client("cloudformation")
    backup = ctx.client("backup")

    stack_name = ctx.unique_name("sim2real-cfnreal-backup-")
    vault_v1 = ctx.unique_name("sim2real-cfnreal-vault-a-")
    vault_v2 = ctx.unique_name("sim2real-cfnreal-vault-b-")

    # The replaced vault outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_vault(backup, vault_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, Backup view ----------------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(vault_v1, _POLICY_V1, _LOCK_V1),
        Tags=_TAGS,
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Vault", vault_v1)
    vault = _assert_vault(backup, vault_v1, _POLICY_V1, _LOCK_V1)
    outputs = _outputs(cfn, stack_id)
    assert outputs == {"Arn": vault["BackupVaultArn"], "Name": vault_v1}, (
        f"GetAtt BackupVaultArn and BackupVaultName must be Backup's: {outputs!r} vs {vault!r}"
    )
    created_at = vault["CreationDate"]

    # ---- 2. in-place update of the mutable AccessPolicy and LockConfiguration ---------------
    rows = _update(ctx, cfn, stack_id, "Vault", _template(vault_v1, _POLICY_V2, _LOCK_V2))
    _assert_updated_in_place(rows, vault_v1)
    _assert_tracks(cfn, stack_id, "Vault", vault_v1)
    vault = _assert_vault(backup, vault_v1, _POLICY_V2, _LOCK_V2)
    assert vault["CreationDate"] == created_at, (
        f"an in-place update keeps the vault: CreationDate {created_at!r} -> {vault!r}"
    )

    # ---- 3. BackupVaultName forces replacement; UpdateReplacePolicy Retain keeps the old ----
    rows = _update(ctx, cfn, stack_id, "Vault", _template(vault_v2, _POLICY_V2, _LOCK_V2))
    _assert_replaced_and_retained(rows, vault_v1, vault_v2)
    _assert_tracks(cfn, stack_id, "Vault", vault_v2)
    _assert_vault(backup, vault_v2, _POLICY_V2, _LOCK_V2)
    old = _assert_vault(backup, vault_v1, _POLICY_V2, _LOCK_V2)
    assert old["CreationDate"] == created_at, f"the retained vault is the first one: {old!r}"

    # ---- 4. DeleteStack: the vault it owns is gone, the retained one stays ------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _poll(
        ctx,
        lambda: _refusal(lambda: backup.describe_backup_vault(BackupVaultName=vault_v2)),
        lambda e: e[0] != "<exists>",
        cap_s=_GONE_S,
        what=f"DescribeBackupVault of {vault_v2!r} refused after DeleteStack",
    )
    assert got == _NOT_FOUND, f"DescribeBackupVault after DeleteStack: {got!r}, not {_NOT_FOUND!r}"
    _assert_vault(backup, vault_v1, _POLICY_V2, _LOCK_V2)


def _template(name: str, policy: dict, lock: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vault": {
                    "Type": "AWS::Backup::BackupVault",
                    # BackupVaultName is create-only, so a new name replaces the vault.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "BackupVaultName": name,
                        "AccessPolicy": policy,
                        "LockConfiguration": lock,
                    },
                },
            },
            "Outputs": {
                "Arn": {"Value": {"Fn::GetAtt": ["Vault", "BackupVaultArn"]}},
                "Name": {"Value": {"Fn::GetAtt": ["Vault", "BackupVaultName"]}},
            },
        }
    )


def _outputs(cfn, stack_id: str) -> dict:
    stack = _stack(cfn, stack_id)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _assert_vault(backup, name: str, policy: dict, lock: dict) -> dict:
    """Backup's view: the vault's name, type and governance lock, and its access policy."""
    vault = backup.describe_backup_vault(BackupVaultName=name)
    got = {
        "BackupVaultName": vault.get("BackupVaultName"),
        "VaultType": vault.get("VaultType"),
        "Locked": vault.get("Locked"),
        "MinRetentionDays": vault.get("MinRetentionDays"),
        "MaxRetentionDays": vault.get("MaxRetentionDays"),
        "LockDate": vault.get("LockDate"),
        "NumberOfRecoveryPoints": vault.get("NumberOfRecoveryPoints"),
    }
    want = {
        "BackupVaultName": name,
        "VaultType": "BACKUP_VAULT",
        "Locked": True,
        **lock,
        "LockDate": None,
        "NumberOfRecoveryPoints": 0,
    }
    assert got == want, f"DescribeBackupVault {name!r} must report {want!r}, got {got!r}"
    stored = backup.get_backup_vault_access_policy(BackupVaultName=name)
    assert (stored["BackupVaultName"], stored["BackupVaultArn"]) == (
        name,
        vault["BackupVaultArn"],
    ), f"GetBackupVaultAccessPolicy must name the vault {name!r}: {stored!r}"
    assert json.loads(stored["Policy"]) == policy, (
        f"vault {name!r} must hold the templated access policy {policy!r}, got {stored['Policy']!r}"
    )
    return vault


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises, or an <exists> pair while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return "<exists>", "the call still succeeds"


def _delete_vault(backup, name: str) -> None:
    """Teardown: drop the governance lock, then the empty vault; a vault not listed is done.

    ListBackupVaults confirms absence, since a missing vault and a denied call answer alike.
    """
    listed = [
        v["BackupVaultName"]
        for page in backup.get_paginator("list_backup_vaults").paginate()
        for v in page["BackupVaultList"]
    ]
    if name not in listed:
        return
    backup.delete_backup_vault_lock_configuration(BackupVaultName=name)
    backup.delete_backup_vault(BackupVaultName=name)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
