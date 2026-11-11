"""create-experiment-definition-invalid-treatment-weights-rejected."""
from __future__ import annotations

import json

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-experiment-definition-invalid-treatment-weights-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperimentDefinition with a negative treatment Weight (the model's minimum is 0.0) is rejected server-side
    with BadRequestException and creates nothing, while valid weights succeed and read back via
    GetExperimentDefinition; client-side validation is off so the bad weight reaches the service."""
    appconfig = ctx.client("appconfig")
    unvalidated = ctx.client("appconfig", config=Config(parameter_validation=False))
    base = _setup_experiment_base(ctx)
    bad_name = ctx.unique_name("sim2real-exp-bad-")

    code, message = _error(
        lambda: unvalidated.create_experiment_definition(
            ApplicationIdentifier=base["app_id"],
            Name=bad_name,
            ConfigurationProfileIdentifier=base["profile_id"],
            EnvironmentIdentifier=base["env_id"],
            FlagKey=base["flag_key"],
            Treatments=[{"Weight": -5.0, "FlagValue": {"Enabled": True}}],
            Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
            AudienceRule=_AUDIENCE_RULE,
        )
    )
    assert code == "BadRequestException", (
        f"expected a server-side BadRequestException for a negative treatment weight, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value '-5.0' at 'treatments.1.member.weight' failed to "
        "satisfy constraint: Member must have value greater than or equal to 0.0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no definition with that name exists in the application (independent read).
    items = appconfig.list_experiment_definitions(ApplicationIdentifier=base["app_id"])["Items"]
    assert not any(item["Name"] == bad_name for item in items), (
        f"a definition named {bad_name!r} exists despite the rejected negative weight"
    )

    # Positive control: the same call with a valid (non-negative) weight succeeds, and the
    # weights it was created with are visible through an independent read (GetExperimentDefinition
    # -- a different operation than the one that mutated).
    good = _create_experiment_definition(ctx, appconfig, base)
    fetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=good["Id"]
    )
    assert fetched["Control"]["Weight"] == 50.0, (
        f"expected the control weight to read back as 50.0, got {fetched['Control']['Weight']!r}"
    )
    assert fetched["Treatments"][0]["Weight"] == 50.0, (
        f"expected the treatment weight to read back as 50.0, got {fetched['Treatments'][0]['Weight']!r}"
    )


_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real-check": CHECK}


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a server-side rejection, but the call succeeded: {result!r}")


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
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=json.dumps(content).encode("utf-8"),
        ContentType="application/json",
    )["VersionNumber"]
    # AppConfig refuses DeleteConfigurationProfile while a hosted version survives under it.
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _create_experiment_definition(ctx, appconfig, base, name=None):
    name = name or ctx.unique_name("sim2real-exp-")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=base["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule=_AUDIENCE_RULE,
        Tags=_TAGS,
    )
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_destroy(appconfig, base["app_id"], def_id))
    return resp


def _safe_destroy(appconfig, app_id, def_id):
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
