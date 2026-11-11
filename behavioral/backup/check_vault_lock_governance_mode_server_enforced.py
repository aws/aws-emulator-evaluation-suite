"""vault-lock-governance-mode-server-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vault-lock-governance-mode-server-enforced"
GROUP = "server-side"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A logically air-gapped vault's compliance-mode lock rejects a PutBackupVaultLockConfiguration
    that loosens retention and keeps the stored retention, while a governance-mode lock on a
    plain vault can be loosened."""
    backup = ctx.client("backup")

    lag_name = ctx.unique_name("sim2real-lag-")
    backup.create_logically_air_gapped_backup_vault(
        BackupVaultName=lag_name,
        MinRetentionDays=10,
        MaxRetentionDays=100,
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
    assert before["MinRetentionDays"] == 10, f"expected MinRetentionDays=10, got {before['MinRetentionDays']}"
    assert before["MaxRetentionDays"] == 100, f"expected MaxRetentionDays=100, got {before['MaxRetentionDays']}"

    # Attempt to loosen (shrink Min, grow Max) the already-immutable lock.
    code, message = _error(
        lambda: backup.put_backup_vault_lock_configuration(
            BackupVaultName=lag_name, MinRetentionDays=1, MaxRetentionDays=36500
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = "Backup vault Lock configuration is immutable and cannot be updated"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = backup.describe_backup_vault(BackupVaultName=lag_name)
    assert after["MinRetentionDays"] == 10, "MinRetentionDays changed despite rejected loosen attempt"
    assert after["MaxRetentionDays"] == 100, "MaxRetentionDays changed despite rejected loosen attempt"

    # Positive control: governance mode is always adjustable.
    plain_name = ctx.unique_name("sim2real-vault-")
    backup.create_backup_vault(
        BackupVaultName=plain_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-vault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=plain_name))

    backup.put_backup_vault_lock_configuration(BackupVaultName=plain_name, MinRetentionDays=10, MaxRetentionDays=100)
    backup.put_backup_vault_lock_configuration(BackupVaultName=plain_name, MinRetentionDays=1, MaxRetentionDays=36500)
    loosened = backup.describe_backup_vault(BackupVaultName=plain_name)
    assert loosened["MinRetentionDays"] == 1, f"expected loosened MinRetentionDays=1, got {loosened['MinRetentionDays']}"
    assert loosened["MaxRetentionDays"] == 36500, f"expected loosened MaxRetentionDays=36500, got {loosened['MaxRetentionDays']}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned: {result!r}")


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
