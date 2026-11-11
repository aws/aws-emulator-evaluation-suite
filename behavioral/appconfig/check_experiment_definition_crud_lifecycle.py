"""experiment-definition-crud-lifecycle."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-definition-crud-lifecycle"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-crud-lifecycle"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create->Get->List->Update->Delete->404 lifecycle for an experiment definition."""
    appconfig = ctx.client("appconfig")
    env = _create_experiment_ready_env(ctx)

    created = appconfig.create_experiment_definition(
        ApplicationIdentifier=env["app_id"],
        Name=ctx.unique_name("sim2real-exp-"),
        ConfigurationProfileIdentifier=env["profile_id"],
        EnvironmentIdentifier=env["env_id"],
        FlagKey=env["flag_key"],
        # $region here is a variable in AppConfig's audience-rule DSL compared against test
        # data, not the AWS API call's region (ctx.region governs that via ctx.client).
        AudienceRule='(eq $region "us-east-1")',
        Control={"Description": "control", "FlagValue": {"Enabled": False}, "Weight": 50},
        Treatments=[{"Description": "treatment-a", "FlagValue": {"Enabled": True}, "Weight": 50}],
        Tags=_TAGS,
    )
    exp_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment(ctx, env["app_id"], exp_id))
    assert created["Status"] == "IDLE", f"new experiment definition must start IDLE, got {created['Status']!r}"
    assert created["FlagKey"] == env["flag_key"], (
        f"expected FlagKey {env['flag_key']!r}, got {created['FlagKey']!r}"
    )
    assert created["Control"]["Weight"] == 50, f"expected control weight 50, got {created['Control']['Weight']!r}"
    assert len(created["Treatments"]) == 1, f"expected 1 treatment, got {len(created['Treatments'])}"

    got = appconfig.get_experiment_definition(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert got["Id"] == exp_id, f"expected Id {exp_id!r}, got {got['Id']!r}"
    assert got["ConfigurationProfileId"] == env["profile_id"], (
        f"expected ConfigurationProfileId {env['profile_id']!r}, got {got['ConfigurationProfileId']!r}"
    )
    assert got["EnvironmentId"] == env["env_id"], (
        f"expected EnvironmentId {env['env_id']!r}, got {got['EnvironmentId']!r}"
    )
    assert got["Status"] == "IDLE", f"expected Status IDLE, got {got['Status']!r}"

    listed = _paginate(appconfig, "list_experiment_definitions", "Items", ApplicationIdentifier=env["app_id"])
    assert exp_id in [item["Id"] for item in listed], f"expected {exp_id!r} in list, got {[i['Id'] for i in listed]}"

    updated = appconfig.update_experiment_definition(
        ApplicationIdentifier=env["app_id"],
        ExperimentDefinitionIdentifier=exp_id,
        Hypothesis="Enabling the flag increases signup rate",
        AudienceDescription="Beta cohort",
    )
    assert updated["Hypothesis"] == "Enabling the flag increases signup rate", (
        f"update response did not echo Hypothesis, got {updated['Hypothesis']!r}"
    )
    assert updated["AudienceDescription"] == "Beta cohort", (
        f"update response did not echo AudienceDescription, got {updated['AudienceDescription']!r}"
    )

    got_after_update = appconfig.get_experiment_definition(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert got_after_update["Hypothesis"] == "Enabling the flag increases signup rate", (
        f"update not reflected in Get Hypothesis, got {got_after_update['Hypothesis']!r}"
    )
    assert got_after_update["AudienceDescription"] == "Beta cohort", (
        f"update not reflected in Get AudienceDescription, got {got_after_update['AudienceDescription']!r}"
    )

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {env['app_id']} and Experiment Definition "
        f"Identifier {exp_id} could not be found for account {account}."
    )
    err = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=env["app_id"], ExperimentDefinitionIdentifier=exp_id
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected 404 after delete, got {err['Code']}"
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    mutate_err = _client_error(
        lambda: appconfig.update_experiment_definition(
            ApplicationIdentifier=env["app_id"],
            ExperimentDefinitionIdentifier=exp_id,
            Hypothesis="should not apply",
        )
    )
    assert mutate_err["Code"] == "ResourceNotFoundException", (
        f"update on a deleted experiment definition must 404, got {mutate_err['Code']}"
    )
    assert mutate_err["Message"] == not_found, f"expected message {not_found!r}, got {mutate_err['Message']!r}"

    listed_after_delete = _paginate(
        appconfig, "list_experiment_definitions", "Items", ApplicationIdentifier=env["app_id"]
    )
    assert exp_id not in [item["Id"] for item in listed_after_delete], (
        f"deleted definition {exp_id!r} still listed: {[i['Id'] for i in listed_after_delete]}"
    )


def _client_error(fn) -> dict[str, str]:
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_experiment(ctx, app_id: str, exp_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _paginate(client, op_name: str, items_key: str, **kwargs) -> list[dict[str, Any]]:
    fn = getattr(client, op_name)
    items: list[dict[str, Any]] = []
    next_token = None
    while True:
        params = dict(kwargs)
        if next_token:
            params["NextToken"] = next_token
        resp = fn(**params)
        items.extend(resp.get(items_key, []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


def _create_experiment_ready_env(ctx) -> dict[str, str]:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )

    flag_key = "simflag"
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    )
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
