"""put-backup-vault-access-policy-malformed-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-backup-vault-access-policy-malformed-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBackupVaultAccessPolicy with a malformed policy is rejected with
    InvalidParameterValueException and stores nothing (GetBackupVaultAccessPolicy reports none);
    a valid policy is stored and read back verbatim."""
    backup = ctx.client("backup")

    vault_name = ctx.unique_name("sim2real-policy-vault-")
    backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-policy"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    code, message = _error(
        lambda: backup.put_backup_vault_access_policy(
            BackupVaultName=vault_name, Policy="{ this is not valid json at all"
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected_message = "Provided Policy is not valid. Please input a valid policy and retry the request."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    get_code, get_message = _error(lambda: backup.get_backup_vault_access_policy(BackupVaultName=vault_name))
    assert get_code == "ResourceNotFoundException", (
        f"a malformed policy was stored on the vault; get raised {get_code!r} instead of ResourceNotFoundException"
    )
    expected_get_message = f"Vault arn:aws:backup:{ctx.region}:{ctx.account}:backup-vault:{vault_name} has no associated vault policy"
    assert get_message == expected_get_message, f"expected message {expected_get_message!r}, got {get_message!r}"

    # Positive control: a valid policy is stored and read back verbatim.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "backup:DeleteBackupVault",
                "Resource": "*",
            }
        ],
    }
    backup.put_backup_vault_access_policy(BackupVaultName=vault_name, Policy=json.dumps(valid_policy))
    ctx.on_cleanup(lambda: backup.delete_backup_vault_access_policy(BackupVaultName=vault_name))
    stored = backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
    got_policy = json.loads(stored["Policy"])
    assert got_policy == valid_policy, f"expected {valid_policy!r}, got {got_policy!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
