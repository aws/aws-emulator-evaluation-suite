"""legal-hold-reason-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "legal-hold-reason-unicode-round-trip"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A legal hold's Title/Description containing unicode (CJK, accented text, emoji) and a
    long-form body round-trips byte-identical through GetLegalHold."""
    backup = ctx.client("backup")
    vault_name = _create_vault(ctx)
    suffix = ctx.unique_name("sim2real-legalhold-")
    title = f"{suffix} \u6cd5\u5f8b\u4fdd\u7ba1 retenci\u00f3n legal \u2603\ufe0f"
    description = (
        "This legal hold covers r\u00e9sum\u00e9-worthy \u6570\u636e with emoji \U0001F512 and a "
        + ("very long filler-text segment " * 40)
        + "tail, to exercise long unicode round-tripping through GetLegalHold."
    )

    now = time.time()
    resp = backup.create_legal_hold(
        Title=title,
        Description=description,
        RecoveryPointSelection={
            "VaultNames": [vault_name],
            "DateRange": {"FromDate": now - 3600, "ToDate": now},
        },
    )
    hold_id = resp["LegalHoldId"]
    ctx.on_cleanup(lambda: _cancel_hold(ctx, hold_id))

    fetched = backup.get_legal_hold(LegalHoldId=hold_id)
    assert fetched["Title"] == title, f"Title mismatch: {fetched['Title']!r} != {title!r}"
    assert fetched["Description"] == description, (
        f"Description mismatch after round-trip: len {len(fetched['Description'])} vs "
        f"{len(description)}, got {fetched['Description'][:80]!r}... expected "
        f"{description[:80]!r}..."
    )



def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(
        BackupVaultName=name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup-vault"},
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            backup.delete_backup_vault(BackupVaultName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _cancel_hold(ctx, hold_id):
    from botocore.exceptions import ClientError

    try:
        ctx.client("backup").cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="sim2real cleanup")
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
