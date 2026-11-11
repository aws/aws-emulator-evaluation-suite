"""get-experiment-definition-not-found-returns-resourcenotfound."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-experiment-definition-not-found-returns-resourcenotfound"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-experiment-definition-not-found"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetExperimentDefinition for a nonexistent id returns ResourceNotFoundException,
    not BadRequestException, even though the parent application genuinely exists."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)

    bogus_id = "nonexistent-experiment-def"
    code, code_msg = _error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=bogus_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Experiment Definition with Application Identifier {app_id} and Experiment "
        f"Definition Identifier {bogus_id} could not be found for account {account}."
    ), f"unexpected message: {code_msg!r}"

    # Positive control: a real experiment definition under the same application resolves fine.
    profile_id = _create_feature_flag_profile(ctx, app_id)
    env_id = _create_environment(ctx, app_id)
    exp_id = _create_simple_experiment_definition(ctx, app_id, profile_id, env_id)
    resp = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    assert resp["Id"] == exp_id, f"expected positive control to resolve {exp_id!r}, got {resp!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
