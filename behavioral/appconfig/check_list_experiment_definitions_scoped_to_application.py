"""list-experiment-definitions-scoped-to-application."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "list-experiment-definitions-scoped-to-application"
GROUP = "data-plane"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-experiment-definitions-scoped-to-application"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentDefinitions, scoped to an application, isolates results from other applications."""
    appconfig = ctx.client("appconfig")

    flag_key_1 = f"flag{uuid.uuid4().hex[:10]}"
    app1_id, env1_id, profile1_id = _setup_feature_flag_app(ctx, appconfig, flag_key_1)
    definition_1 = appconfig.create_experiment_definition(
        ApplicationIdentifier=app1_id,
        Name=ctx.unique_name("sim2real-behav-expdef1-"),
        ConfigurationProfileIdentifier=profile1_id,
        EnvironmentIdentifier=env1_id,
        FlagKey=flag_key_1,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def1_id = definition_1["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app1_id, ExperimentDefinitionIdentifier=def1_id, DeleteType="DESTROY"
        )
    )

    flag_key_2 = f"flag{uuid.uuid4().hex[:10]}"
    app2_id, env2_id, profile2_id = _setup_feature_flag_app(ctx, appconfig, flag_key_2)
    definition_2 = appconfig.create_experiment_definition(
        ApplicationIdentifier=app2_id,
        Name=ctx.unique_name("sim2real-behav-expdef2-"),
        ConfigurationProfileIdentifier=profile2_id,
        EnvironmentIdentifier=env2_id,
        FlagKey=flag_key_2,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def2_id = definition_2["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app2_id, ExperimentDefinitionIdentifier=def2_id, DeleteType="DESTROY"
        )
    )

    scoped_to_app1 = appconfig.list_experiment_definitions(ApplicationIdentifier=app1_id)["Items"]
    scoped_ids = [item["Id"] for item in scoped_to_app1]

    assert def1_id in scoped_ids
    assert def2_id not in scoped_ids
    for item in scoped_to_app1:
        assert item["ApplicationId"] == app1_id


def _setup_feature_flag_app(ctx, appconfig, flag_key: str):
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-ff-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )
    profile_id = profile["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = json.dumps(
        {"flags": {flag_key: {"name": flag_key}}, "values": {flag_key: {"enabled": True}}, "version": "1"}
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
    return app_id, env_id, profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
