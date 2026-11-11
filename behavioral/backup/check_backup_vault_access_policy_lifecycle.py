"""backup-vault-access-policy-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "backup-vault-access-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBackupVaultAccessPolicy persists a policy; DeleteBackupVaultAccessPolicy removes it so Get
    returns ResourceNotFoundException, and a second Delete succeeds without restoring it."""
    backup = ctx.client("backup")
    account_id = ctx.account
    vault_name = ctx.unique_name("sim2real-vaultpolicy-")

    backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-vaultpolicy"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SimparityAllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "backup:DescribeBackupVault",
                "Resource": "*",
            }
        ],
    }
    backup.put_backup_vault_access_policy(BackupVaultName=vault_name, Policy=json.dumps(policy))

    got = backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
    persisted = json.loads(got["Policy"])
    assert persisted["Statement"][0]["Sid"] == "SimparityAllowDescribe", (
        f"expected Sid 'SimparityAllowDescribe', got {persisted['Statement'][0].get('Sid')!r}"
    )
    assert persisted["Statement"][0]["Action"] == "backup:DescribeBackupVault", (
        f"expected Action 'backup:DescribeBackupVault', got {persisted['Statement'][0].get('Action')!r}"
    )

    backup.delete_backup_vault_access_policy(BackupVaultName=vault_name)

    code, message = _error(lambda: backup.get_backup_vault_access_policy(BackupVaultName=vault_name))
    assert code == "ResourceNotFoundException", (
        f"expected GetBackupVaultAccessPolicy to fail with ResourceNotFoundException after delete, got {code!r}"
    )
    assert message == (
        f"Vault arn:aws:backup:{ctx.region}:{ctx.account}:backup-vault:{vault_name} "
        "has no associated vault policy"
    ), f"actual_message={message!r}"

    backup.delete_backup_vault_access_policy(BackupVaultName=vault_name)  # idempotent: no-op success

    still_gone_code, still_gone_message = _error(
        lambda: backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
    )
    assert still_gone_code == "ResourceNotFoundException", (
        "expected the policy to remain absent (not resurrected) after a second, idempotent delete, "
        f"got {still_gone_code!r}"
    )
    assert still_gone_message == (
        f"Vault arn:aws:backup:{ctx.region}:{ctx.account}:backup-vault:{vault_name} "
        "has no associated vault policy"
    ), f"actual_message={still_gone_message!r}"


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
