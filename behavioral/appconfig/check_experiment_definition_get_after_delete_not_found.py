"""experiment-definition-get-after-delete-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-definition-get-after-delete-not-found"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-get-after-delete-not-found"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExperimentDefinition on a permanently-deleted id returns ResourceNotFoundException,
    not stale data, while a sibling definition that was not touched remains fully readable."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_feature_flag_profile(ctx, app_id)

    target = _create_experiment_definition(ctx, app_id, profile_id, env_id)
    control = _create_experiment_definition(ctx, app_id, profile_id, env_id)
    target_id, control_id = target["Id"], control["Id"]

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id,
        ExperimentDefinitionIdentifier=target_id,
        DeleteType="DESTROY",
    )

    err = _client_error(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=target_id
        )
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the deleted definition, got {err['Code']!r}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {target_id} could not be found for account {account}."
    )
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    # Positive control: the untouched sibling definition is still fully readable.
    got_control = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=control_id
    )
    assert got_control["Id"] == control_id, (
        f"expected control Id {control_id!r}, got {got_control['Id']!r}"
    )
    assert got_control["Name"] == control["Name"], (
        f"expected control Name {control['Name']!r}, got {got_control['Name']!r}"
    )
    assert got_control["Status"] == "IDLE", (
        f"expected untouched control definition to remain IDLE, got {got_control['Status']!r}"
    )

    # Effect fully absent from the list view too, while the control remains listed.
    ids = _poll_until(
        lambda: _list_experiment_definition_ids(appconfig, app_id),
        lambda ids: target_id not in ids,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert control_id in ids, (
        f"expected control {control_id!r} to remain in the list view, got {ids!r}"
    )


def _client_error(fn):
    """Return the botocore Error dict if fn() raises ClientError.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator that
    still serves a deleted resource is the strongest signal available, and returning None
    would turn that into an error-code mismatch that reads like a naming difference.
    """
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected ResourceNotFoundException for the deleted definition, but the call "
        f"SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )
    return env_id


def _create_feature_flag_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )
    return profile_id


def _safe_delete_experiment_definition(ctx, app_id, exp_id):
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=exp_id,
            DeleteType="DESTROY",
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "ConflictException",
        ):
            raise


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key=None, name=None):
    appconfig = ctx.client("appconfig")
    flag_key = flag_key or ctx.unique_name("sim2real-flag-")
    name = name or ctx.unique_name("sim2real-exp-")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=name,
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        AudienceRule='(eq $country "US")',
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_experiment_definition(ctx, app_id, resp["Id"]))
    return resp


def _list_experiment_definition_ids(appconfig, app_id):
    return {
        item["Id"]
        for item in appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)["Items"]
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
