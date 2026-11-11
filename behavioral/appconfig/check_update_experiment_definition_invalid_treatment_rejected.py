"""update-experiment-definition-invalid-treatment-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-experiment-definition-invalid-treatment-rejected"
GROUP = "experiment"
SERVICES = ["appconfig"]

_FLAG_KEY = "checkoutbutton"
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-experiment-invalid-treatment"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentDefinition replacing a single Treatment with 6, one more than the modelled
    list maximum of 5, is accepted with Status IDLE, and GetExperimentDefinition then returns the 6 Treatments."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_feature_flag_profile(ctx, app_id)
    exp_id = _create_simple_experiment_definition(ctx, app_id, profile_id, env_id, flag_key=_FLAG_KEY)

    before = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    assert len(before["Treatments"]) == 1, f"expected 1 treatment before the update, got {before['Treatments']}"

    six_treatments = [
        {"Weight": 10.0, "FlagValue": {"Enabled": True}} for _ in range(6)
    ]
    updated = appconfig.update_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=exp_id,
        Treatments=six_treatments,
    )
    assert updated["Status"] == "IDLE", f"expected status IDLE after the update, got {updated['Status']!r}"

    confirmed = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    assert len(confirmed["Treatments"]) == 6, f"expected 6 persisted treatments, got {confirmed['Treatments']}"


# ===== helpers =====
def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(
            ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
        )
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            DeletionProtectionCheck="BYPASS",
        )
    )
    return profile_id


def _create_simple_experiment_definition(
    ctx, app_id, profile_id, env_id, flag_key="my-feature-flag", name=None
):
    appconfig = ctx.client("appconfig")
    exp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    exp_id = exp["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            DeleteType="DESTROY",
        )
    )
    return exp_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

