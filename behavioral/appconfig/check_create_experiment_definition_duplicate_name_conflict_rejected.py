"""create-experiment-definition-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "create-experiment-definition-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second experiment definition with the same Name in the same app/profile/environment
    fails with ConflictException and leaves the original unchanged; a distinct name succeeds."""
    appconfig = ctx.client("appconfig")
    prereqs = _create_feature_flag_app(ctx)
    shared_name = ctx.unique_name("sim2real-behav-dupexp-")

    original = _create_experiment_definition(ctx, prereqs, shared_name)
    original_id = original["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_experiment_definition(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=original_id,
                DeleteType="DESTROY",
            )
        )
    )

    code, message = _error(lambda: _create_experiment_definition(ctx, prereqs, shared_name))
    assert code == "ConflictException", f"expected ConflictException on a duplicate Name, got {code!r}"
    expected = (
        f"Experiment definition with name '{shared_name}' already exists for application "
        f"{prereqs['app_id']}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: exactly one definition with this name exists, and it is unchanged
    listing = appconfig.list_experiment_definitions(ApplicationIdentifier=prereqs["app_id"])
    matches = [item for item in listing["Items"] if item["Name"] == shared_name]
    assert len(matches) == 1, f"expected exactly one definition named {shared_name!r}, found {len(matches)}"
    assert matches[0]["Id"] == original_id, (
        f"expected the surviving definition named {shared_name!r} to be the original "
        f"{original_id!r}, got {matches[0]['Id']!r}"
    )
    unchanged = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=original_id
    )
    assert unchanged["CreatedAt"] == original["CreatedAt"], (
        f"expected the rejected duplicate create to leave CreatedAt at {original['CreatedAt']!r}, "
        f"got {unchanged['CreatedAt']!r}"
    )

    # positive control: a distinct name in the same app/profile/environment succeeds
    other_name = ctx.unique_name("sim2real-behav-otherexp-")
    other = _create_experiment_definition(ctx, prereqs, other_name)
    other_id = other["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_experiment_definition(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=other_id,
                DeleteType="DESTROY",
            )
        )
    )
    assert other_id != original_id, f"expected a distinct Id from {original_id!r}, got {other_id!r}"

    # terminal read: an independent GetExperimentDefinition confirms the distinct-name
    # definition is actually readable at the destination, not just echoed by the create call
    other_read = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=other_id
    )
    assert other_read["Name"] == other_name, (
        f"expected the independently-read distinct-name definition to have Name {other_name!r}, "
        f"got {other_read['Name']!r}"
    )


_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-create-experiment-definition-duplicate-name-conflict-rejected"}


def _error(fn):
    """Call fn(); return the (Error.Code, Error.Message) of its ClientError; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_cleanup(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_feature_flag_app(ctx) -> dict[str, Any]:
    """Create an Application with a feature-flag ConfigurationProfile + hosted
    configuration version + Environment, wired for experiments."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_configuration_profile(
                ApplicationId=app_id,
                ConfigurationProfileId=profile_id,
                DeletionProtectionCheck="BYPASS",
            )
        )
    )

    flag_key = ctx.unique_name("flag-").replace("_", "-")
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=profile_id,
                VersionNumber=version_number,
            )
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_environment(
                ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
            )
        )
    )

    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id, "flag_key": flag_key}


def _create_experiment_definition(ctx, prereqs: dict[str, Any], name: str) -> dict[str, Any]:
    appconfig = ctx.client("appconfig")
    return appconfig.create_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=prereqs["profile_id"],
        EnvironmentIdentifier=prereqs["env_id"],
        FlagKey=prereqs["flag_key"],
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
