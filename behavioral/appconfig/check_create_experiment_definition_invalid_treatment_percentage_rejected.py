"""create-experiment-definition-invalid-treatment-percentage-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-experiment-definition-invalid-treatment-percentage-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperimentDefinition against a Freeform-type configuration profile is rejected with
    BadRequestException and creates nothing; the feature-flags profile succeeds."""
    appconfig = ctx.client("appconfig")

    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "pctflag"
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key)
    freeform_profile_id = _create_freeform_profile(ctx, app_id)

    bad_name = ctx.unique_name("sim2real-exp-bad-")

    def _create_against_freeform_profile():
        return appconfig.create_experiment_definition(
            ApplicationIdentifier=app_id,
            Name=bad_name,
            ConfigurationProfileIdentifier=freeform_profile_id,
            EnvironmentIdentifier=env_id,
            FlagKey=flag_key,
            AudienceRule="(eq 1 1)",
            Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": 50},
            Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": 50}],
        )

    code, message = _error(_create_against_freeform_profile)
    assert code == "BadRequestException", str(code)
    expected = (
        f"Configuration profile {freeform_profile_id} cannot be used for experiments. Experiment "
        "definitions require a configuration profile of type AWS.AppConfig.FeatureFlags."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no experiment definition with the intended name was created.
    listed = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)
    names = [item["Name"] for item in listed.get("Items", [])]
    assert bad_name not in names, "freeform-profile experiment definition was created despite BadRequestException"

    # Positive control: pointing at the actual feature-flags profile succeeds.
    good_name = ctx.unique_name("sim2real-exp-good-")
    good = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=good_name,
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule="(eq 1 1)",
        Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": 50},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": 50}],
    )
    good_id = good["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=good_id, DeleteType="DESTROY"
        )
    )
    fetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=good_id
    )
    assert fetched["Name"] == good_name, f"expected Name={good_name!r}, got {fetched.get('Name')!r}"


def _error(fn) -> tuple[str, str | None]:
    """Call fn() and return its (error code, error message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_freeform_profile(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-freeform-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    content = json.dumps({"key": "value"}).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    version_number = version["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
    return profile_id


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str) -> str:
    appconfig = ctx.client("appconfig")
    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-ffprofile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )
    content = json.dumps(
        {
            "version": "1",
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    version_number = version["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
    return profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
