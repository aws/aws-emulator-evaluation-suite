"""restore-access-vault-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "restore-access-vault-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new air-gapped vault lists no restore access vaults, CreateRestoreAccessBackupVault without
    an MPA team fails with InvalidRequestException, and RevokeRestoreAccessBackupVault with a
    nonconforming ARN fails with InvalidParameterValueException."""
    backup = ctx.client("backup")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    source_vault_name = ctx.unique_name("sim2real-lag-src-")

    created_source = backup.create_logically_air_gapped_backup_vault(
        BackupVaultName=source_vault_name,
        MinRetentionDays=7,
        MaxRetentionDays=30,
    )
    source_vault_arn = created_source["BackupVaultArn"]
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=source_vault_name))

    _poll_until(
        lambda: backup.describe_backup_vault(BackupVaultName=source_vault_name),
        lambda r: r["VaultState"] == "AVAILABLE",
        timeout_s=180.0,
    )

    # State-machine baseline: no restore access vault has ever been granted for this vault.
    listed = backup.list_restore_access_backup_vaults(BackupVaultName=source_vault_name)[
        "RestoreAccessBackupVaults"
    ]
    assert listed == [], f"expected no restore access vaults on a fresh vault, got {listed}"

    # Without an MPA approval team associated, the create request is rejected -- the specific,
    # documented precondition failure, not a generic error.
    code, message = _error(
        lambda: backup.create_restore_access_backup_vault(SourceBackupVaultArn=source_vault_arn)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = "Cannot create restore access backup vault. No MPA approval team associated with the backup vault."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # No restore access vault was created as a side effect of the rejected call.
    listed_after = backup.list_restore_access_backup_vaults(BackupVaultName=source_vault_name)[
        "RestoreAccessBackupVaults"
    ]
    assert listed_after == [], (
        f"rejected CreateRestoreAccessBackupVault must not create anything, got {listed_after}"
    )

    # Revoking a restore-access vault that was never granted is rejected with the specific
    # not-found error rather than a silent no-op success.
    fake_restore_access_arn = (
        f"arn:aws:backup:{ctx.region}:{account_id}:restore-access-backup-vault:"
        f"{ctx.unique_name('sim2real-fake-rav-')}"
    )
    # Revoking a restore-access vault with a syntactically-nonconforming ARN is rejected with the
    # specific invalid-parameter error rather than a silent no-op success.
    revoke_code, revoke_message = _error(
        lambda: backup.revoke_restore_access_backup_vault(
            BackupVaultName=source_vault_name, RestoreAccessBackupVaultArn=fake_restore_access_arn
        )
    )
    assert revoke_code == "InvalidParameterValueException", f"actual_code={revoke_code}"
    expected_revoke_message = "The provided restore access backup vault ARN is not valid."
    assert revoke_message == expected_revoke_message, f"expected message {expected_revoke_message!r}, got {revoke_message!r}"

    # Independent terminal read: the rejected revoke did not create, remove or otherwise change
    # anything -- the vault's restore-access state is still exactly what it was before the call.
    listed_final = backup.list_restore_access_backup_vaults(BackupVaultName=source_vault_name)[
        "RestoreAccessBackupVaults"
    ]
    assert listed_final == [], (
        f"rejected RevokeRestoreAccessBackupVault must not change restore-access state, got {listed_final}"
    )


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
    SUCCEEDS once timeout_s has passed raises, because a target accepting a call real AWS refuses
    must not read as a code mismatch."""
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

