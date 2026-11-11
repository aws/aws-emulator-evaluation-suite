"""experiment-definition-treatment-payload-round-trip."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-definition-treatment-payload-round-trip"
GROUP = "representation"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-treatment-payload-round-trip"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-treatment experiment definition with unicode Name/Hypothesis and nested FlagValue
    AttributeValues (strings, float, boolean, arrays) round-trips unchanged through
    GetExperimentDefinition.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id, version_number = _create_feature_flag_profile(ctx, app_id, flag_key)
    _deploy_configuration(ctx, app_id, env_id, profile_id, version_number)

    unicode_name = ctx.unique_name("sim2real-behav-exp-") + "-\u5b9e\u9a8c-\U0001f680"
    hypothesis = "\u5047\u8bbe\uff1a\u542f\u7528\u65b0\u529f\u80fd\u4f1a\u63d0\u9ad8\u70b9\u51fb\u7387 \U0001f3af"

    treatment_1 = {
        "Weight": 30.0,
        "Description": "\u5904\u7406\u7ec4\u4e00 \U0001f3af",
        "FlagValue": {
            "Enabled": True,
            "AttributeValues": {
                "variantlabel": {"StringValue": "\u53d8\u4f53\u4e00 \U0001f600"},
                "priority": {"NumberValue": 3.5},
                "isfeatured": {"BooleanValue": True},
                "tags": {"StringArray": ["a", "b", "\u65e5\u672c\u8a9e"]},
                "scores": {"NumberArray": [1.5, 2.25]},
            },
        },
    }
    treatment_2 = {
        "Weight": 20.0,
        "Description": "\u5904\u7406\u7ec4\u4e8c",
        "FlagValue": {"Enabled": False},
    }
    control = {
        "Weight": 50.0,
        "Description": "\u5bf9\u7167\u7ec4",
        "FlagValue": {"Enabled": False},
    }

    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=unicode_name,
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[treatment_1, treatment_2],
        Control=control,
        AudienceRule='(eq $country "JP")',
        Hypothesis=hypothesis,
        Tags=_TAGS,
    )
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, def_id))

    got = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )

    assert got["Name"] == unicode_name, f"Name mismatch: expected {unicode_name!r}, got {got['Name']!r}"
    assert got["Hypothesis"] == hypothesis, (
        f"Hypothesis mismatch: expected {hypothesis!r}, got {got['Hypothesis']!r}"
    )

    got_treatments = got["Treatments"]
    assert len(got_treatments) == 2, f"expected 2 treatments, got {len(got_treatments)}"

    for i, (original, got_t) in enumerate(zip([treatment_1, treatment_2], got_treatments)):
        assert got_t["Weight"] == original["Weight"], (
            f"treatment[{i}] Weight mismatch: expected {original['Weight']!r}, got {got_t['Weight']!r}"
        )
        assert got_t["Description"] == original["Description"], (
            f"treatment[{i}] Description mismatch: expected {original['Description']!r}, "
            f"got {got_t['Description']!r}"
        )
        assert got_t["FlagValue"] == original["FlagValue"], (
            f"treatment[{i}] FlagValue mismatch: expected {original['FlagValue']!r}, got {got_t['FlagValue']!r}"
        )

    assert got["Control"]["Weight"] == control["Weight"], (
        f"Control Weight mismatch: expected {control['Weight']!r}, got {got['Control']['Weight']!r}"
    )
    assert got["Control"]["Description"] == control["Description"], (
        f"Control Description mismatch: expected {control['Description']!r}, got {got['Control']['Description']!r}"
    )
    assert got["Control"]["FlagValue"] == control["FlagValue"], (
        f"Control FlagValue mismatch: expected {control['FlagValue']!r}, got {got['Control']['FlagValue']!r}"
    )


def _flag_key() -> str:
    return "flag" + uuid.uuid4().hex[:10]


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    return env_id


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str):
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
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": False}},
            "version": "1",
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )
    return profile_id, version["VersionNumber"]


def _deploy_configuration(ctx, app_id: str, env_id: str, profile_id: str, version_number) -> int:
    """AppConfig requires an existing, completed deployment for a configuration profile
    before an experiment definition can be created against the feature flag it stores."""
    appconfig = ctx.client("appconfig")
    strategy = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-depstrat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )
    strategy_id = strategy["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    dep = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = dep["DeploymentNumber"]
    completed = _poll_until(
        lambda: appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        ),
        lambda resp: resp["State"] == "COMPLETE",
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert completed["State"] == "COMPLETE", f"deployment did not complete: {completed!r}"
    return deployment_number


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
