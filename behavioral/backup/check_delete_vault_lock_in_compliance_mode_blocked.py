"""delete-vault-lock-in-compliance-mode-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-vault-lock-in-compliance-mode-blocked"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBackupVaultLockConfiguration rejects ChangeableForDays below 3 and applies no lock,
    accepts 3, and the lock can still be deleted inside that grace window."""
    backup = ctx.client("backup")
    vault_name = _create_vault(ctx)

    # break one thing: a cooling-off period shorter than the mandatory 3-day floor
    code, message = _error(
        lambda: backup.put_backup_vault_lock_configuration(
            BackupVaultName=vault_name, ChangeableForDays=1, MinRetentionDays=7, MaxRetentionDays=30
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    assert message == (
        "Backup vault Lock configuration changeable days must be between 3 and 36,500."
    ), f"actual_message={message!r}"

    # effect absent: no lock was applied to the vault
    desc = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert not desc.get("Locked"), f"vault unexpectedly locked after a rejected Put: {desc}"

    # positive control: a ChangeableForDays value exactly at the documented floor (3) succeeds
    backup.put_backup_vault_lock_configuration(
        BackupVaultName=vault_name, ChangeableForDays=3, MinRetentionDays=7, MaxRetentionDays=30
    )
    locked_desc = _poll_vault_locked(ctx, vault_name, expected=True)
    assert locked_desc.get("MinRetentionDays") == 7, f"expected MinRetentionDays=7, got {locked_desc}"
    assert locked_desc.get("MaxRetentionDays") == 30, f"expected MaxRetentionDays=30, got {locked_desc}"

    # within the grace window, the documented escape hatch actually removes the lock state
    backup.delete_backup_vault_lock_configuration(BackupVaultName=vault_name)
    unlocked_desc = _poll_vault_locked(ctx, vault_name, expected=False)
    assert not unlocked_desc.get("Locked"), "vault lock removal during grace time did not take effect"


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(
        BackupVaultName=name, BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"}
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: backup.delete_backup_vault(BackupVaultName=name)))
    return name


def _poll_vault_locked(ctx, vault_name, expected: bool, timeout_s: float = 30, interval_s: float = 2):
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = backup.describe_backup_vault(BackupVaultName=vault_name)
        if bool(desc.get("Locked")) == expected:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"vault {vault_name} Locked did not become {expected} within {timeout_s}s: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
