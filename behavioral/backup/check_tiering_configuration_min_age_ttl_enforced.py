"""tiering-configuration-min-age-ttl-enforced."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.config import Config
from botocore.exceptions import ClientError

CHECK = "tiering-configuration-min-age-ttl-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTieringConfiguration rejects TieringDownSettingsInDays below the 60-day floor (sent
    past client-side validation) and persists nothing, while exactly 60 is accepted and
    round-trips through Get/ListTieringConfigurations."""
    backup = ctx.client("backup")
    unvalidated_backup = ctx.client("backup", config=Config(parameter_validation=False))
    vault_name = _create_vault(ctx)

    bad_name = _config_name(ctx, "bad")
    code, message = _error(
        lambda: unvalidated_backup.create_tiering_configuration(
            TieringConfiguration={
                "TieringConfigurationName": bad_name,
                "BackupVaultName": vault_name,
                "ResourceSelection": [
                    {"Resources": ["*"], "ResourceType": "S3", "TieringDownSettingsInDays": 30}
                ],
            }
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected_message = "Invalid TieringDownSettingsInDays. Days must be between 60 and 36500"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the below-floor configuration was never created
    absent_code, absent_message = _error(lambda: backup.get_tiering_configuration(TieringConfigurationName=bad_name))
    assert absent_code == "ResourceNotFoundException", f"expected config absent, got {absent_code}"
    expected_absent_message = "Cannot find tiering configuration"
    assert absent_message == expected_absent_message, f"expected message {expected_absent_message!r}, got {absent_message!r}"

    # positive control: exactly at the documented 60-day floor succeeds and round-trips
    good_name = _config_name(ctx, "good")
    backup.create_tiering_configuration(
        TieringConfiguration={
            "TieringConfigurationName": good_name,
            "BackupVaultName": vault_name,
            "ResourceSelection": [
                {"Resources": ["*"], "ResourceType": "S3", "TieringDownSettingsInDays": 60}
            ],
        }
    )
    ctx.on_cleanup(
        lambda: _safe_call(lambda: backup.delete_tiering_configuration(TieringConfigurationName=good_name))
    )

    fetched = backup.get_tiering_configuration(TieringConfigurationName=good_name)["TieringConfiguration"]
    got_days = fetched["ResourceSelection"][0]["TieringDownSettingsInDays"]
    assert got_days == 60, f"expected TieringDownSettingsInDays 60 to round-trip, got {got_days}"

    names = {c["TieringConfigurationName"] for c in _list_all_configs(backup)}
    assert good_name in names, f"{good_name} not visible in ListTieringConfigurations"


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


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _config_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real_tiering_{tag}_")
    return "".join(ch if ch.isalnum() else "_" for ch in raw)


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(BackupVaultName=name)
    ctx.on_cleanup(lambda: _safe_call(lambda: backup.delete_backup_vault(BackupVaultName=name)))
    return name


def _list_all_configs(backup):
    configs = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = backup.list_tiering_configurations(**kwargs)
        configs.extend(resp["TieringConfigurations"])
        token = resp.get("NextToken")
        if not token:
            return configs


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
