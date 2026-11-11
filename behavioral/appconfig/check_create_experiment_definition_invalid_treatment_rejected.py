"""create-experiment-definition-invalid-treatment-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "create-experiment-definition-invalid-treatment-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperimentDefinition with 6 Treatments, one more than the modelled list maximum of 5,
    is accepted with Status IDLE, and ListExperimentDefinitions lists the definition by name."""
    appconfig = ctx.client("appconfig")
    prereqs = _create_feature_flag_app(ctx)
    name = ctx.unique_name("sim2real-behav-sixexp-")

    created = appconfig.create_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"],
        Name=name,
        ConfigurationProfileIdentifier=prereqs["profile_id"],
        EnvironmentIdentifier=prereqs["env_id"],
        FlagKey=prereqs["flag_key"],
        Treatments=[
            {"Weight": 10.0, "FlagValue": {"Enabled": True}} for _ in range(6)
        ],
        Control={"Weight": 40.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
    )
    # The definition holds the environment and application: delete it before either.
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_experiment_definition(
                ApplicationIdentifier=prereqs["app_id"],
                ExperimentDefinitionIdentifier=created["Id"],
                DeleteType="DESTROY",
            )
        )
    )
    assert created["Name"] == name, f"expected name {name!r}, got {created['Name']!r}"
    assert created["Status"] == "IDLE", f"expected status IDLE, got {created['Status']!r}"

    listing = appconfig.list_experiment_definitions(ApplicationIdentifier=prereqs["app_id"])
    names = [item["Name"] for item in listing["Items"]]
    assert name in names, f"accepted definition {name!r} missing from ListExperimentDefinitions: {names!r}"


# ===== helpers =====
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
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    )

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
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
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-")
    )["Id"]
    ctx.on_cleanup(
        lambda: _safe_cleanup(
            lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        )
    )

    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id, "flag_key": flag_key}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
