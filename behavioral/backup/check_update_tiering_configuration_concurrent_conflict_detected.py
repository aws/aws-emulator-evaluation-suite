"""update-tiering-configuration-concurrent-conflict-detected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-tiering-configuration-concurrent-conflict-detected"
GROUP = "concurrency"
SERVICES = ["backup"]
_CONFLICT_MESSAGE = (
    "AWS Backup can't perform the action that you requested until it finishes performing a previous action. Try again later."
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateTieringConfiguration calls on one configuration each succeed or lose
    with ConflictException, at least one succeeds, and the persisted TieringDownSettingsInDays is
    a successful racer's value, never a refused racer's."""
    backup = ctx.client("backup")
    vault_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    config_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

    vault_name = ctx.unique_name("sim2real-behav-vault-")
    backup.create_backup_vault(BackupVaultName=vault_name, BackupVaultTags=vault_tags)
    ctx.on_cleanup(lambda: _safe(lambda: backup.delete_backup_vault(BackupVaultName=vault_name)))

    config_name = ctx.unique_name("sim2real_behav_tiering_")
    backup.create_tiering_configuration(
        TieringConfiguration={
            "TieringConfigurationName": config_name,
            "BackupVaultName": vault_name,
            "ResourceSelection": [
                {"Resources": ["*"], "ResourceType": "S3", "TieringDownSettingsInDays": 60}
            ],
        },
        TieringConfigurationTags=config_tags,
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: backup.delete_tiering_configuration(TieringConfigurationName=config_name))
    )

    def _update(days: int):
        return days, _call_capture(
            lambda: backup.update_tiering_configuration(
                TieringConfigurationName=config_name,
                TieringConfiguration={
                    "BackupVaultName": vault_name,
                    "ResourceSelection": [
                        {"Resources": ["*"], "ResourceType": "S3", "TieringDownSettingsInDays": days}
                    ],
                },
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, 90), pool.submit(_update, 120)]
        results = [f.result() for f in futures]

    winners = [days for days, (_result, code, _msg) in results if code is None]
    assert winners, f"neither concurrent UpdateTieringConfiguration call succeeded: {results}"
    for _days, (_result, code, message) in results:
        if code is None:
            continue
        assert code == "ConflictException", (
            f"a racing UpdateTieringConfiguration may only lose with ConflictException, "
            f"got {code} ({message!r})"
        )
        assert message == _CONFLICT_MESSAGE, (
            f"ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}"
        )

    # The persisted value must be one the API reported as accepted.
    final = backup.get_tiering_configuration(TieringConfigurationName=config_name)
    final_days = final["TieringConfiguration"]["ResourceSelection"][0]["TieringDownSettingsInDays"]
    assert final_days in winners, (
        f"persisted TieringDownSettingsInDays={final_days} is not the value of a racer that "
        f"succeeded ({winners})"
    )


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _call_capture(fn: Callable[[], Any]) -> tuple[Any, str | None, str | None]:
    from botocore.exceptions import ClientError

    try:
        return fn(), None, None
    except ClientError as err:
        error = err.response.get("Error", {})
        return None, error.get("Code"), error.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
