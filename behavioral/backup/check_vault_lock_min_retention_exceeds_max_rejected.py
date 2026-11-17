"""vault-lock-min-retention-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vault-lock-min-retention-exceeds-max-rejected"
GROUP = "vault-lock-min-retention-exceeds-max-rejected"
SERVICES = ["backup"]

_INVALID_RANGE = (
    "InvalidParameterValueException",
    "Backup vault Lock configuration retention days must be between 1 and 36,500, and minimum "
    "must be less than or equal to maximum.",
)


def expect_error(fn, code, message) -> None:
    """Call fn(); assert it raises exactly (code, message). An unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code} ({message!r}), but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBackupVaultLockConfiguration with MinRetentionDays greater than MaxRetentionDays is
    rejected and leaves the vault unlocked; equal min/max on the same vault locks it."""
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-vaultlockrange-")
    backup.create_backup_vault(BackupVaultName=vault_name)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    expect_error(
        lambda: backup.put_backup_vault_lock_configuration(
            BackupVaultName=vault_name, MinRetentionDays=30, MaxRetentionDays=7, ChangeableForDays=3
        ),
        *_INVALID_RANGE,
    )

    after_rejection = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert after_rejection.get("Locked") is False, (
        f"the rejected lock configuration must leave the vault unlocked; Locked="
        f"{after_rejection.get('Locked')!r}"
    )
    assert "MinRetentionDays" not in after_rejection, (
        f"a rejected PutBackupVaultLockConfiguration must not set MinRetentionDays; got "
        f"{after_rejection.get('MinRetentionDays')!r}"
    )
    assert "MaxRetentionDays" not in after_rejection, (
        f"a rejected PutBackupVaultLockConfiguration must not set MaxRetentionDays; got "
        f"{after_rejection.get('MaxRetentionDays')!r}"
    )

    # Positive control: the equal-bounds boundary, on the SAME vault, succeeds and locks it.
    backup.put_backup_vault_lock_configuration(
        BackupVaultName=vault_name, MinRetentionDays=7, MaxRetentionDays=7, ChangeableForDays=3
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault_lock_configuration(BackupVaultName=vault_name))

    after_control = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert after_control["Locked"] is True, (
        f"the equal-bounds lock configuration must apply; Locked={after_control.get('Locked')!r}"
    )
    assert after_control["MinRetentionDays"] == 7, (
        f"expected MinRetentionDays=7, got {after_control.get('MinRetentionDays')!r}"
    )
    assert after_control["MaxRetentionDays"] == 7, (
        f"expected MaxRetentionDays=7, got {after_control.get('MaxRetentionDays')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
