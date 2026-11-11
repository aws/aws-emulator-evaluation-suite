"""experiment-definition-delete-then-get-404."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-definition-delete-then-get-404"
GROUP = "state-machine"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteExperimentDefinition completes, GetExperimentDefinition on the same id
    returns ResourceNotFoundException (it succeeded and returned the live definition before
    deletion, proving the 404 is caused by the delete and not a setup mistake)."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = _flag_key()
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key)
    def_id, _created = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    before = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    assert before["Id"] == def_id, f"expected pre-delete GetExperimentDefinition Id {def_id!r}, got {before['Id']!r}"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
    )

    # _poll_until_error_code raises if the specific code is never observed within the deadline,
    # so reaching the next line already proves the independent read now sees ResourceNotFoundException.
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Experiment Definition with Application Identifier {app_id} and Experiment Definition "
        f"Identifier {def_id} could not be found for account {account}."
    )
    get_err = _poll_until_error_code(
        lambda: appconfig.get_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        ),
        timeout_s=20.0,
    )
    assert get_err["Message"] == not_found, f"expected message {not_found!r}, got {get_err['Message']!r}"

    # A mutation on the dead id fails too -- delete is not just invisible to reads.
    update_err = _client_error(
        lambda: appconfig.update_experiment_definition(
            ApplicationIdentifier=app_id,
            ExperimentDefinitionIdentifier=def_id,
            Hypothesis="resurrected hypothesis",
        )
    )
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected UpdateExperimentDefinition on deleted id to raise ResourceNotFoundException, "
        f"got {update_err['Code']!r}"
    )
    assert update_err["Message"] == not_found, (
        f"expected message {not_found!r}, got {update_err['Message']!r}"
    )


_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "appconfig-experiment-definition-delete-then-get-404",
}


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
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_error_code(fn, timeout_s=20.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return err.response["Error"]
            last = err.response["Error"]
        time.sleep(interval_s)
    raise AssertionError(
        f"ResourceNotFoundException not observed within {timeout_s}s; last outcome was {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
