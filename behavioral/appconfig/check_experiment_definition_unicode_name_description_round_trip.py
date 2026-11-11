"""experiment-definition-unicode-name-description-round-trip."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "experiment-definition-unicode-name-description-round-trip"
GROUP = "representation"
SERVICES = ["appconfig"]

_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode in Name and Hypothesis survives CreateExperimentDefinition byte-identically."""
    appconfig = ctx.client("appconfig")
    flag_key = f"flag{uuid.uuid4().hex[:10]}"
    app_id, env_id, profile_id = _setup_feature_flag_app(ctx, appconfig, flag_key)

    unique_suffix = uuid.uuid4().hex[:8]
    name = f"实验-{unique_suffix}-Ω-🚀"[:64]
    hypothesis = "假设：启用 Ω 标志会提高转化率 🎯 — expected lift ≥ 5% (café, naïve, Zürich)"

    definition = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=name,
        Hypothesis=hypothesis,
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def_id = definition["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    )

    assert definition["Name"] == name, f"create response Name: expected {name!r}, got {definition['Name']!r}"
    assert definition["Hypothesis"] == hypothesis, (
        f"create response Hypothesis: expected {hypothesis!r}, got {definition['Hypothesis']!r}"
    )

    fetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert fetched["Name"] == name, f"get response Name: expected {name!r}, got {fetched['Name']!r}"
    assert fetched["Hypothesis"] == hypothesis, (
        f"get response Hypothesis: expected {hypothesis!r}, got {fetched['Hypothesis']!r}"
    )


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
    appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    return app_id, env_id, profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
