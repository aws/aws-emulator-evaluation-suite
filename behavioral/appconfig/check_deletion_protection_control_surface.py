"""deletion-protection-control-surface."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-control-surface"
GROUP = 'configuration-profile'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deletion-protection-control-surface"}


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _restore_account_settings(ac, original: dict) -> None:
    try:
        dp = original.get("DeletionProtection", {}) or {}
        ac.update_account_settings(
            DeletionProtection={
                "Enabled": dp.get("Enabled", False),
                "ProtectionPeriodInMinutes": dp.get("ProtectionPeriodInMinutes", 15),
            }
        )
    except Exception:
        pass


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """Enabled deletion protection round-trips; a never-active profile is deleted under APPLY,
    BYPASS and ACCOUNT_DEFAULT, and each deleted id then 404s on read and on a second delete."""
    ac = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    original_settings = ac.get_account_settings()
    try:
        ac.update_account_settings(
            DeletionProtection={"Enabled": True, "ProtectionPeriodInMinutes": 15}
        )
        settings = ac.get_account_settings()
        assert settings["DeletionProtection"]["Enabled"] is True, (
            f"expected DeletionProtection.Enabled=True after UpdateAccountSettings, got {settings}"
        )
        assert settings["DeletionProtection"]["ProtectionPeriodInMinutes"] == 15, (
            f"expected DeletionProtection.ProtectionPeriodInMinutes=15 after "
            f"UpdateAccountSettings, got {settings}"
        )

        app_id = ac.create_application(
            Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
        )["Id"]
        ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))

        def _create_profile():
            return ac.create_configuration_profile(
                ApplicationId=app_id,
                Name=ctx.unique_name("sim2real-behav-cp-"),
                LocationUri="hosted",
                Tags=_TAGS,
            )["Id"]

        def _assert_deleted(cp_id):
            not_found = (
                f"Configuration Profile with Application Id {app_id} and Configuration Profile "
                f"Id {cp_id} could not be found for account {account_id}."
            )
            read_code, read_message = _client_error(
                lambda: ac.get_configuration_profile(
                    ApplicationId=app_id, ConfigurationProfileId=cp_id
                )
            )
            assert read_code == "ResourceNotFoundException", (
                f"expected ResourceNotFoundException reading deleted profile {cp_id}, "
                f"got {read_code}"
            )
            assert read_message == not_found, f"expected {not_found!r}, got {read_message!r}"
            delete_again_code, delete_again_message = _client_error(
                lambda: ac.delete_configuration_profile(
                    ApplicationId=app_id,
                    ConfigurationProfileId=cp_id,
                    DeletionProtectionCheck="BYPASS",
                )
            )
            assert delete_again_code == "ResourceNotFoundException", (
                f"expected ResourceNotFoundException deleting already-deleted profile "
                f"{cp_id}, got {delete_again_code}"
            )
            assert delete_again_message == not_found, (
                f"expected {not_found!r}, got {delete_again_message!r}"
            )

        # Protection only arms off serving activity (deployment + GetConfiguration); this profile
        # was never active, so APPLY must permit the delete.
        cp_apply = _create_profile()
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_apply,
            DeletionProtectionCheck="APPLY",
        )
        _assert_deleted(cp_apply)

        # BYPASS must always delete, regardless of activity.
        cp_bypass = _create_profile()
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_bypass,
            DeletionProtectionCheck="BYPASS",
        )
        _assert_deleted(cp_bypass)

        # ACCOUNT_DEFAULT is a valid enum value and defers to account settings.
        cp_default = _create_profile()
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_default,
            DeletionProtectionCheck="ACCOUNT_DEFAULT",
        )
        _assert_deleted(cp_default)
    finally:
        _restore_account_settings(ac, original_settings)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
