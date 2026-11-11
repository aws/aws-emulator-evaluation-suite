"""update-experiment-definition-invalid-schedule-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-experiment-definition-invalid-schedule-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentDefinition with a negative treatment Weight, sent past client-side
    validation, raises BadRequestException and leaves the weights unchanged; a valid weight update
    succeeds.
    """
    from botocore.config import Config

    appconfig = ctx.client("appconfig")
    unvalidated = ctx.client("appconfig", config=Config(parameter_validation=False))
    base = _setup_experiment_base(ctx)
    created = _create_experiment_definition(ctx, appconfig, base)
    def_id = created["Id"]
    assert created["Treatments"][0]["Weight"] == 50.0

    code, message = _error(
        lambda: unvalidated.update_experiment_definition(
            ApplicationIdentifier=base["app_id"],
            ExperimentDefinitionIdentifier=def_id,
            Treatments=[{"Weight": -10.0, "FlagValue": {"Enabled": True}}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = (
        "1 validation error detected: Value '-10.0' at 'treatments.1.member.weight' failed to "
        "satisfy constraint: Member must have value greater than or equal to 0.0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the prior weight is unchanged.
    unchanged = appconfig.get_experiment_definition(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    assert unchanged["Treatments"][0]["Weight"] == 50.0

    # Positive control: an in-range weight update succeeds and persists.
    updated = appconfig.update_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        ExperimentDefinitionIdentifier=def_id,
        Treatments=[{"Weight": 75.0, "FlagValue": {"Enabled": True}}],
    )
    assert updated["Treatments"][0]["Weight"] == 75.0
    confirmed = appconfig.get_experiment_definition(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )
    assert confirmed["Treatments"][0]["Weight"] == 75.0


_AUDIENCE_RULE = '(eq $country "US")'


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _setup_experiment_base(ctx, flag_key="expflag1"):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-")
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
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
