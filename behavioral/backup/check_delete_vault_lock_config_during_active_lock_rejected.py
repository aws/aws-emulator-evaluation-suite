"""delete-vault-lock-config-during-active-lock-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-vault-lock-config-during-active-lock-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBackupVaultLockConfiguration on a logically air-gapped vault fails with
    InvalidRequestException and the lock stays; a governance-mode lock on a plain vault is
    removable."""
    backup = ctx.client("backup")

    lag_name = ctx.unique_name("sim2real-lag-")
    backup.create_logically_air_gapped_backup_vault(
        BackupVaultName=lag_name,
        MinRetentionDays=7,
        MaxRetentionDays=30,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-lag"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=lag_name))

    before = _poll_until(
        lambda: backup.describe_backup_vault(BackupVaultName=lag_name),
        lambda r: r["VaultState"] in ("AVAILABLE", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert before["VaultState"] == "AVAILABLE", f"LAG vault provisioning failed: {before}"
    assert before["Locked"] is True, f"LAG vault must be locked immediately on creation: {before}"
    assert before["MinRetentionDays"] == 7, f"expected MinRetentionDays=7, got {before.get('MinRetentionDays')}"

    code, message = _error(lambda: backup.delete_backup_vault_lock_configuration(BackupVaultName=lag_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Backup vault Lock configuration is immutable and cannot be deleted", f"unexpected message {message!r}"

    after = backup.describe_backup_vault(BackupVaultName=lag_name)
    assert after["Locked"] is True, "vault lock was removed despite the rejected delete call"
    assert after["MinRetentionDays"] == 7, "vault lock retention setting changed despite rejection"

    # Positive control: a *governance* mode lock (no ChangeableForDays) on a
    # plain vault is always removable, unlike the immutable compliance lock above.
    plain_name = ctx.unique_name("sim2real-vault-")
    backup.create_backup_vault(
        BackupVaultName=plain_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-vault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=plain_name))

    backup.put_backup_vault_lock_configuration(BackupVaultName=plain_name, MinRetentionDays=1, MaxRetentionDays=100)
    locked = backup.describe_backup_vault(BackupVaultName=plain_name)
    assert locked["Locked"] is True, f"governance-mode lock did not take effect: {locked}"

    backup.delete_backup_vault_lock_configuration(BackupVaultName=plain_name)
    unlocked = backup.describe_backup_vault(BackupVaultName=plain_name)
    assert unlocked["Locked"] is False, "governance-mode lock could not be removed"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
