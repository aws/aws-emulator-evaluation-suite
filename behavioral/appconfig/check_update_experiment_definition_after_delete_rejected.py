"""update-experiment-definition-after-delete-rejected."""
from __future__ import annotations

import json

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-experiment-definition-after-delete-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-experiment-definition-after-delete-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExperimentDefinition against a destroyed definition id is rejected and does not
    resurrect the resource, while updating a live definition still works normally."""
    appconfig = ctx.client("appconfig")
    flag_key = ctx.unique_name("flag-")
    base = _create_base(ctx, flag_key)
    app_id = base["app_id"]

    deleted_definition = _create_experiment_definition(ctx, base, flag_key)
    deleted_def_id = deleted_definition["Id"]
    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=deleted_def_id,
        DeleteType="DESTROY",
    )

    code, message = _error(
        lambda: appconfig.update_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=deleted_def_id,
            Hypothesis="resurrected hypothesis",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a destroyed definition, got {code!r}"
    )
    expected = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {deleted_def_id} could not be found for account {ctx.account}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The resource was not resurrected by the rejected update.
    get_code, get_message = _error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=deleted_def_id
        )
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected the destroyed definition to stay gone after the rejected update, "
        f"got {get_code!r}"
    )
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    # Positive control: updating a live definition works and persists.
    live_definition = _create_experiment_definition(ctx, base, flag_key)
    live_def_id = live_definition["Id"]
    ctx.on_cleanup(lambda: _safe_delete_definition(appconfig, app_id, live_def_id))

    updated = appconfig.update_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=live_def_id,
        Hypothesis="the new treatment increases signups",
    )
    assert updated["Hypothesis"] == "the new treatment increases signups", (
        f"expected the update response to echo the new hypothesis, got {updated['Hypothesis']!r}"
    )

    refetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=live_def_id
    )
    assert refetched["Hypothesis"] == "the new treatment increases signups", (
        f"expected the update to persist independently of the mutating call's own response, "
        f"got {refetched['Hypothesis']!r}"
    )


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel.
    """
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call against the destroyed definition to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _safe_delete_definition(appconfig, app_id, def_id):
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_base(ctx, flag_key):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-prof-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = json.dumps(
        {
            "version": "1",
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    return {"app_id": app_id, "profile_id": profile_id, "env_id": env_id}


def _treatment(weight, enabled=True):
    return {"Weight": weight, "FlagValue": {"Enabled": enabled}}


def _create_experiment_definition(ctx, base, flag_key, name=None):
    appconfig = ctx.client("appconfig")
    return appconfig.create_experiment_definition(
        ApplicationIdentifier=base["app_id"],
        Name=name or ctx.unique_name("sim2real-behav-exp-"),
        ConfigurationProfileIdentifier=base["profile_id"],
        EnvironmentIdentifier=base["env_id"],
        FlagKey=flag_key,
        AudienceRule="(eq 1 1)",
        Control=_treatment(50.0),
        Treatments=[_treatment(50.0)],
        Tags=_TAGS,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
