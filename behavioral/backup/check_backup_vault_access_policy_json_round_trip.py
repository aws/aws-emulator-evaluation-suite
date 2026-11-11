"""backup-vault-access-policy-json-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "backup-vault-access-policy-json-round-trip"
GROUP = "server-side"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A complex, multi-statement IAM policy document (nested Conditions, list-valued
    Principal/Action) set via PutBackupVaultAccessPolicy is returned value-for-value identical
    -- not merely present -- via GetBackupVaultAccessPolicy."""
    backup = ctx.client("backup")
    vault_name = _create_vault(ctx)
    vault_arn = backup.describe_backup_vault(BackupVaultName=vault_name)["BackupVaultArn"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountCopyIn",
                "Effect": "Allow",
                "Principal": {"AWS": [f"arn:aws:iam::{account_id}:root"]},
                "Action": ["backup:CopyIntoBackupVault"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:backup:{ctx.region}:{account_id}:backup-vault:*"},
                },
            },
            {
                "Sid": "DenyDeleteWithoutMfa",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "backup:DeleteRecoveryPoint",
                "Resource": vault_arn,
                "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
            },
        ],
    }
    backup.put_backup_vault_access_policy(BackupVaultName=vault_name, Policy=json.dumps(policy))
    fetched = json.loads(backup.get_backup_vault_access_policy(BackupVaultName=vault_name)["Policy"])

    assert fetched["Version"] == policy["Version"], f"expected Version {policy['Version']!r}, got {fetched['Version']!r}"
    assert len(fetched["Statement"]) == 2, f"expected 2 statements, got {len(fetched['Statement'])}: {fetched['Statement']!r}"
    by_sid = {s["Sid"]: s for s in fetched["Statement"]}

    allow = by_sid["AllowCrossAccountCopyIn"]
    assert allow["Effect"] == "Allow", f"expected Effect 'Allow' on AllowCrossAccountCopyIn, got {allow['Effect']!r}"
    # AWS may normalize a single-element Action/Principal-AWS list to a bare scalar when it
    # stores the policy; compare value-for-value tolerant of that scalar<->list normalization.
    assert _as_list(allow["Action"]) == ["backup:CopyIntoBackupVault"], (
        f"expected Action ['backup:CopyIntoBackupVault'], got {allow['Action']!r}"
    )
    assert _as_list(allow["Principal"]["AWS"]) == [f"arn:aws:iam::{account_id}:root"], (
        f"expected Principal.AWS [{account_id}:root], got {allow['Principal']['AWS']!r}"
    )
    assert allow["Condition"] == policy["Statement"][0]["Condition"], (
        f"expected Condition {policy['Statement'][0]['Condition']!r}, got {allow['Condition']!r}"
    )

    deny = by_sid["DenyDeleteWithoutMfa"]
    assert deny["Effect"] == "Deny", f"expected Effect 'Deny' on DenyDeleteWithoutMfa, got {deny['Effect']!r}"
    assert deny["Resource"] == vault_arn, f"expected Resource {vault_arn!r}, got {deny['Resource']!r}"
    assert deny["Condition"] == policy["Statement"][1]["Condition"], (
        f"expected Condition {policy['Statement'][1]['Condition']!r}, got {deny['Condition']!r}"
    )


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    vault_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    backup.create_backup_vault(BackupVaultName=name, BackupVaultTags=vault_tags)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
