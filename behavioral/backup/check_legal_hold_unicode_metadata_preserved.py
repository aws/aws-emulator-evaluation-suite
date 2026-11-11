"""legal-hold-unicode-metadata-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "legal-hold-unicode-metadata-preserved"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode characters (CJK, emoji, accented Latin) in a legal hold's
    Title and Description survive CreateLegalHold and are returned
    byte-for-byte unchanged by GetLegalHold.
    """
    backup = ctx.client("backup")

    vault_name = ctx.unique_name("sim2real-lh-vault-")
    backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-lh-vault"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    title = f"{ctx.unique_name('sim2real-legalhold-')}-\u6cd5\u5f8b\u4fdd\u7559-\U0001f512"
    description = "Caf\u00e9 r\u00e9tention l\u00e9gale \u2014 \u30ed\u30f3\u30c9\u30f3\u4fdd\u6301 \U0001f512\U0001f4dd"

    created = backup.create_legal_hold(
        Title=title,
        Description=description,
        RecoveryPointSelection={
            "VaultNames": [vault_name],
            "DateRange": {"FromDate": 0, "ToDate": time.time()},
        },
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-legalhold"},
    )
    hold_id = created["LegalHoldId"]
    ctx.on_cleanup(lambda: backup.cancel_legal_hold(LegalHoldId=hold_id, CancelDescription="test cleanup"))

    assert created["Title"] == title, f"CreateLegalHold Title mutated: {created['Title']!r} != {title!r}"
    assert created["Description"] == description, (
        f"CreateLegalHold Description mutated: {created['Description']!r} != {description!r}"
    )

    got = backup.get_legal_hold(LegalHoldId=hold_id)
    assert got["Title"] == title, f"Title mutated: {got['Title']!r} != {title!r}"
    assert got["Description"] == description, f"Description mutated: {got['Description']!r} != {description!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
