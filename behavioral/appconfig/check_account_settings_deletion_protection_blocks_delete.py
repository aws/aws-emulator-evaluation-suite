"""account-settings-deletion-protection-blocks-delete."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "account-settings-deletion-protection-blocks-delete"
GROUP = "server-side"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deletion-protection"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """With account DeletionProtection on, a never-read profile still deletes under forced APPLY;
    a deployed, read profile with a hosted version is refused (BadRequestException) and survives;
    once that version is removed, a BYPASS delete removes it."""
    appconfig = ctx.client("appconfig")

    original = appconfig.get_account_settings()
    orig_deletion = dict(original.get("DeletionProtection", {}))
    orig_enabled = orig_deletion.get("Enabled", False)
    orig_period = orig_deletion.get("ProtectionPeriodInMinutes", 60)

    ctx.on_cleanup(
        lambda: appconfig.update_account_settings(
            DeletionProtection={"Enabled": orig_enabled, "ProtectionPeriodInMinutes": orig_period}
        )
    )

    appconfig.update_account_settings(
        DeletionProtection={"Enabled": True, "ProtectionPeriodInMinutes": 15}
    )
    settings = appconfig.get_account_settings()
    assert settings["DeletionProtection"]["Enabled"] is True, settings
    assert settings["DeletionProtection"]["ProtectionPeriodInMinutes"] == 15, settings

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-dpapp-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    # Positive control: a profile never read via GetConfiguration is not "active", so even a
    # forced APPLY delete succeeds; a stub rejecting every APPLY delete fails here.
    control_profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-dpcontrol-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )["Id"]
    appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=control_profile_id, DeletionProtectionCheck="APPLY"
    )
    control_code, control_message = _error_code(
        lambda: appconfig.get_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=control_profile_id
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"never-accessed profile should delete cleanly under forced APPLY, got get-back code={control_code}"
    )
    assert control_message == f"Configuration Profile with Application Id {app_id} and Configuration Profile Id {control_profile_id} could not be found for account {ctx.account}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {control_message!r}"
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-dpenv-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-dpprofile-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )["Id"]

    profile_deleted = {"done": False}

    def _cleanup_profile() -> None:
        if not profile_deleted["done"]:
            # AWS refuses DeleteConfigurationProfile, even with BYPASS, while hosted configuration
            # versions exist under the profile, so clear them first.
            for item in appconfig.list_hosted_configuration_versions(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            ).get("Items", []):
                appconfig.delete_hosted_configuration_version(
                    ApplicationId=app_id,
                    ConfigurationProfileId=profile_id,
                    VersionNumber=item["VersionNumber"],
                )
            appconfig.delete_configuration_profile(
                ApplicationId=app_id,
                ConfigurationProfileId=profile_id,
                DeletionProtectionCheck="BYPASS",
            )

    ctx.on_cleanup(_cleanup_profile)

    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=b'{"greeting": "hello"}',
        ContentType="application/json",
    )["VersionNumber"]

    # The predefined AppConfig.AllAtOnce strategy bakes for 10 minutes, past the 180 s poll
    # budget; a zero-duration, zero-bake strategy completes in seconds.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-dpstrategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]

    state = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"],
        lambda s: s == "COMPLETE",
        timeout_s=180,
        interval_s=3,
    )
    assert state == "COMPLETE", f"deployment never reached COMPLETE, last observed state={state}"

    # Mark the profile/environment as "actively used" the same way real clients do.
    appconfig.get_configuration(
        Application=app_id, Environment=env_id, Configuration=profile_id, ClientId="sim2real-client"
    )

    # APPLY forces the check; by default resources created in the past hour are exempt.
    code, message = _error_code(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="APPLY",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == f"Cannot delete configuration profile {profile_id} because there are still hosted configuration versions existing under it.", (
        f"expected the exact BadRequestException message AWS returns, got {message!r}"
    )

    still_there = appconfig.get_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )
    assert still_there["Id"] == profile_id, "blocked delete must not have removed the profile"

    # A profile with hosted configuration versions cannot be deleted under any
    # DeletionProtectionCheck, so remove the version first.
    appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
    )

    appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS"
    )
    profile_deleted["done"] = True

    code_after_bypass, message_after_bypass = _error_code(
        lambda: appconfig.get_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    assert code_after_bypass == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after bypassed delete, got {code_after_bypass}"
    )
    assert message_after_bypass == f"Configuration Profile with Application Id {still_there['ApplicationId']} and Configuration Profile Id {still_there['Id']} could not be found for account {ctx.account}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message_after_bypass!r}"
    )


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
