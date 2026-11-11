"""experiment-definition-full-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "experiment-definition-full-lifecycle"
GROUP = "experiment"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-full-lifecycle"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Experiment definition CRUD: create starts IDLE, updates show on the next Get, List
    reflects the current set, and DESTROY delete makes it 404 and drops it from the list."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = "expflag"
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key)

    exp_id, created = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)
    assert created["Status"] == "IDLE", f"new experiment definition must start IDLE, got {created['Status']}"
    assert created["FlagKey"] == flag_key, f"expected FlagKey {flag_key!r}, got {created['FlagKey']!r}"
    assert len(created["Treatments"]) == 1, f"expected 1 treatment, got {len(created['Treatments'])}"
    assert created["Treatments"][0]["Weight"] == 50.0, f"expected treatment weight 50.0, got {created['Treatments'][0]['Weight']}"
    assert created["Control"]["Weight"] == 50.0, f"expected control weight 50.0, got {created['Control']['Weight']}"

    got = appconfig.get_experiment_definition(ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)
    assert got["Status"] == "IDLE", f"expected Status IDLE, got {got['Status']}"
    assert got["EnvironmentId"] == env_id, f"expected EnvironmentId {env_id!r}, got {got['EnvironmentId']!r}"
    assert got["ConfigurationProfileId"] == profile_id, (
        f"expected ConfigurationProfileId {profile_id!r}, got {got['ConfigurationProfileId']!r}"
    )

    updated = appconfig.update_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=exp_id,
        Hypothesis="Checkout redesign increases conversion",
    )
    assert updated["Hypothesis"] == "Checkout redesign increases conversion", (
        f"update response did not echo the new Hypothesis, got {updated['Hypothesis']!r}"
    )

    got2 = appconfig.get_experiment_definition(ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id)
    assert got2["Hypothesis"] == "Checkout redesign increases conversion", "update not reflected in Get"

    listing = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)["Items"]
    assert any(item["Id"] == exp_id for item in listing), "experiment definition missing from List"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY")

    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {exp_id} could not be found for account {account}."
    )
    err = _client_error(lambda: appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected 404 after delete, got {err['Code']}"
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    mutate_err = _client_error(lambda: appconfig.update_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Hypothesis="should not apply"))
    assert mutate_err["Code"] == "ResourceNotFoundException", (
        f"update on a deleted experiment definition must 404, got {mutate_err['Code']}"
    )
    assert mutate_err["Message"] == not_found, f"expected message {not_found!r}, got {mutate_err['Message']!r}"

    listing_after = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)["Items"]
    assert not any(item["Id"] == exp_id for item in listing_after), "deleted definition still listed"



def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_environment(
        ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS")))
    return env_id


def _create_feature_flag_profile(ctx, app_id, flag_key):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS")))
    content = json.dumps({
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
        "version": "1",
    }).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=content, ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version)))
    return profile_id


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key,
                                   control_weight=50.0, treatment_weight=50.0):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": True}, "Weight": control_weight},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": treatment_weight}],
    )
    exp_id = resp["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY")))
    return exp_id, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
