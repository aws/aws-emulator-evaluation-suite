"""experiment-definition-lifecycle-create-active-update-delete."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-definition-lifecycle-create-active-update-delete"
GROUP = "state-machine"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExperimentDefinition -> GetExperimentDefinition -> UpdateExperimentDefinition ->
    the updated fields persist across a fresh Get -> DeleteExperimentDefinition(DESTROY) ->
    a subsequent Get raises ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    base = _setup_experiment_base(ctx)
    name = ctx.unique_name("sim2real-exp-")

    created = appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=base["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Hypothesis="initial hypothesis",
        Tags=_TAGS,
    )
    def_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_destroy(appconfig, base["app_id"], def_id))

    assert created["Name"] == name, f"expected created Name {name!r}, got {created['Name']!r}"
    assert created["Hypothesis"] == "initial hypothesis", (
        f"expected created Hypothesis 'initial hypothesis', got {created['Hypothesis']!r}"
    )
    assert created["Status"] == "IDLE", f"expected new definition Status IDLE, got {created['Status']!r}"

    got = appconfig.get_experiment_definition(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    assert got["Name"] == name, f"expected Get Name {name!r}, got {got['Name']!r}"
    assert got["Hypothesis"] == "initial hypothesis", (
        f"expected Get Hypothesis 'initial hypothesis', got {got['Hypothesis']!r}"
    )
    assert got["Status"] == "IDLE", f"expected Get Status IDLE, got {got['Status']!r}"

    updated = appconfig.update_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        ExperimentDefinitionIdentifier=def_id,
        Hypothesis="revised hypothesis",
        LaunchCriteria="launch when p-value < 0.05",
    )
    assert updated["Hypothesis"] == "revised hypothesis", (
        f"expected Update response Hypothesis 'revised hypothesis', got {updated['Hypothesis']!r}"
    )

    # The mutation must be durably persisted, not just echoed by the Update response.
    got2 = appconfig.get_experiment_definition(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    assert got2["Hypothesis"] == "revised hypothesis", (
        f"expected post-update Get Hypothesis 'revised hypothesis', got {got2['Hypothesis']!r}"
    )
    assert got2["LaunchCriteria"] == "launch when p-value < 0.05", (
        f"expected post-update Get LaunchCriteria 'launch when p-value < 0.05', "
        f"got {got2.get('LaunchCriteria')!r}"
    )

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        ExperimentDefinitionIdentifier=def_id,
        DeleteType="DESTROY",
    )

    err = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected 404 after delete, got {err['Code']!r}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {base['app_id']} and Experiment Definition "
        f"Identifier {def_id} could not be found for account {account}."
    )
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"


_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_destroy(appconfig, app_id, def_id):
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _setup_experiment_base(ctx, flag_key="expflag1"):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    content = {
        "version": "1",
        "flags": {flag_key: {"name": flag_key}},
        "values": {flag_key: {"enabled": True}},
    }
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
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
