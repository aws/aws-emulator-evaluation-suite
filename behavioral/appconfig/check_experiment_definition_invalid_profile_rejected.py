"""experiment-definition-invalid-profile-rejected."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-definition-invalid-profile-rejected"
GROUP = "state-machine"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperimentDefinition naming a configuration profile that does not exist raises
    ResourceNotFoundException and persists nothing, while the same call for a real profile succeeds.
    """
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key)

    # Negative: a bogus ConfigurationProfileIdentifier must be rejected before anything is
    # persisted.
    bogus_profile_id = "zzzzzzz"
    rejected_name = ctx.unique_name("sim2real-behav-exp-bad-")
    err = _client_error(
        lambda: appconfig.create_experiment_definition(
            ApplicationIdentifier=app_id,
            Name=rejected_name,
            ConfigurationProfileIdentifier=bogus_profile_id,
            EnvironmentIdentifier=env_id,
            FlagKey=flag_key,
            Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
            Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
            AudienceRule='(eq $country "US")',
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a bogus ConfigurationProfileIdentifier, got {err['Code']!r}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    expected = (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id "
        f"{bogus_profile_id} could not be found for account {account}."
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Effect absent: no definition with the rejected name exists.
    listed = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)
    assert all(item["Name"] != rejected_name for item in listed["Items"]), (
        f"rejected name {rejected_name!r} must not appear in list_experiment_definitions"
    )

    # Positive control: the identical request against the real profile succeeds.
    def_id, created = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)
    assert def_id, "create_experiment_definition must return a non-empty Id"

    # Terminal read is independent of the mutating CreateExperimentDefinition call.
    fetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert fetched["Status"] == "IDLE", (
        f"expected the positive control's definition to read back IDLE via GetExperimentDefinition, "
        f"got {fetched['Status']!r}"
    )
    assert fetched["ConfigurationProfileId"] == profile_id, (
        f"expected {profile_id!r}, got {fetched['ConfigurationProfileId']!r}"
    )


_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-invalid-profile"}


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


def _create_feature_flag_profile(ctx, app_id: str, flag_key: str) -> str:
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
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
        )
    )
    return profile_id


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key, name=None):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
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
    def_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, def_id))
    return def_id, resp


def _safe_delete_experiment_definition(ctx, app_id: str, def_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available and must not be reported as a
    bare code mismatch (nor leak an untracked resource).
    """
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

