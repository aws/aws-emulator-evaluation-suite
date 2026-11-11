"""logically-air-gapped-vault-create."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logically-air-gapped-vault-create"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLogicallyAirGappedBackupVault produces a vault that appears in ListBackupVaults with the
    air-gapped vault type/state set."""
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-lag-")

    backup.create_logically_air_gapped_backup_vault(
        BackupVaultName=vault_name,
        MinRetentionDays=7,
        MaxRetentionDays=30,
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    def _find():
        vaults = backup.list_backup_vaults(ByVaultType="LOGICALLY_AIR_GAPPED_BACKUP_VAULT")["BackupVaultList"]
        matches = [v for v in vaults if v["BackupVaultName"] == vault_name]
        return matches[0] if matches else None

    found = _poll_until(_find, lambda m: m is not None and m["VaultState"] == "AVAILABLE", timeout_s=180.0)
    assert found["VaultType"] == "LOGICALLY_AIR_GAPPED_BACKUP_VAULT", (
        f"expected VaultType=LOGICALLY_AIR_GAPPED_BACKUP_VAULT, got {found['VaultType']!r}"
    )
    assert found["MinRetentionDays"] == 7, f"expected MinRetentionDays=7, got {found['MinRetentionDays']!r}"
    assert found["MaxRetentionDays"] == 30, f"expected MaxRetentionDays=30, got {found['MaxRetentionDays']!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
