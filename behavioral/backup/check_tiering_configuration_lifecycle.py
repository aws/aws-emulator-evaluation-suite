"""tiering-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tiering-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tiering configuration: create -> update (tiering rules reflected) -> delete -> Get raises
    ResourceNotFoundException, an Update on the dead name also fails, and it disappears from
    ListTieringConfigurations."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_tier_").replace("-", "_")

    backup.create_tiering_configuration(
        TieringConfiguration={
            "TieringConfigurationName": name,
            "BackupVaultName": "*",
            "ResourceSelection": [
                {"Resources": ["*"], "TieringDownSettingsInDays": 60, "ResourceType": "S3"},
            ],
        },
        TieringConfigurationTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_tier"},
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            backup.delete_tiering_configuration(TieringConfigurationName=name)

    ctx.on_cleanup(_cleanup)

    got = backup.get_tiering_configuration(TieringConfigurationName=name)["TieringConfiguration"]
    got_days = got["ResourceSelection"][0]["TieringDownSettingsInDays"]
    assert got_days == 60, f"expected TieringDownSettingsInDays == 60 right after create, got {got_days}"

    listed = backup.list_tiering_configurations()["TieringConfigurations"]
    assert any(t["TieringConfigurationName"] == name for t in listed), (
        f"{name} not visible in ListTieringConfigurations after create"
    )

    backup.update_tiering_configuration(
        TieringConfigurationName=name,
        TieringConfiguration={
            "BackupVaultName": "*",
            "ResourceSelection": [
                {"Resources": ["*"], "TieringDownSettingsInDays": 120, "ResourceType": "S3"},
            ],
        },
    )

    updated = backup.get_tiering_configuration(TieringConfigurationName=name)["TieringConfiguration"]
    updated_days = updated["ResourceSelection"][0]["TieringDownSettingsInDays"]
    assert updated_days == 120, f"expected TieringDownSettingsInDays == 120 after update, got {updated_days}"

    backup.delete_tiering_configuration(TieringConfigurationName=name)
    deleted["done"] = True

    code, message = _error(lambda: backup.get_tiering_configuration(TieringConfigurationName=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on Get after delete, got {code}"
    expected_message = "Cannot find tiering configuration"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: backup.update_tiering_configuration(
            TieringConfigurationName=name,
            TieringConfiguration={
                "BackupVaultName": "*",
                "ResourceSelection": [
                    {"Resources": ["*"], "TieringDownSettingsInDays": 90, "ResourceType": "S3"},
                ],
            },
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected Update on the deleted {name} to fail with ResourceNotFoundException, got {update_code}"
    )
    expected_update_message = "Cannot find tiering configuration"
    assert update_message == expected_update_message, f"expected message {expected_update_message!r}, got {update_message!r}"

    listed_after = backup.list_tiering_configurations()["TieringConfigurations"]
    assert not any(t["TieringConfigurationName"] == name for t in listed_after), (
        f"{name} still visible in ListTieringConfigurations after delete"
    )


def _error(fn, *, timeout_s: float = 0.0, interval_s: float = 3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS once timeout_s has passed raises."""
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
