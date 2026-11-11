"""list-experiment-definitions-reflects-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-experiment-definitions-reflects-lifecycle"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-experiment-lifecycle"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExperimentDefinitions lists every new definition of the application and, after one is
    deleted, excludes only that one while the sibling stays listed."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)

    flag_key_a = _flag_key()
    profile_id_a = _create_feature_flag_profile(ctx, app_id, flag_key_a)
    def_id_a, _ = _create_experiment_definition(ctx, app_id, profile_id_a, env_id, flag_key_a)

    flag_key_b = _flag_key()
    profile_id_b = _create_feature_flag_profile(ctx, app_id, flag_key_b)
    def_id_b, _ = _create_experiment_definition(ctx, app_id, profile_id_b, env_id, flag_key_b)

    listed = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)
    ids = {item["Id"] for item in listed["Items"]}
    assert def_id_a in ids, f"expected newly created definition {def_id_a} in listed ids {ids}"
    assert def_id_b in ids, f"expected sibling definition {def_id_b} in listed ids {ids}"

    appconfig.delete_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id_a, DeleteType="DESTROY"
    )

    listed_after = _poll_until(
        lambda: appconfig.list_experiment_definitions(ApplicationIdentifier=app_id),
        lambda resp: def_id_a not in {item["Id"] for item in resp["Items"]},
        timeout_s=20.0,
    )
    ids_after = {item["Id"] for item in listed_after["Items"]}
    assert def_id_a not in ids_after, f"expected deleted definition {def_id_a} absent, still in {ids_after}"
    assert def_id_b in ids_after, (
        f"expected sibling definition {def_id_b} to remain listed after deleting {def_id_a}, "
        f"got {ids_after} -- a wholesale wipe would drop it too"
    )


# ===== helpers =====

def _flag_key() -> str:
    return "flag" + uuid.uuid4().hex[:10]


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id: str) -> str:
    appconfig = ctx.client("appconfig")
    env = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )
    env_id = env["Id"]
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: appconfig.delete_environment(
                ApplicationId=app_id, EnvironmentId=env_id, DeletionProtectionCheck="BYPASS"
            )
        )
    )
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
        lambda: _retry_delete(
            lambda: appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, DeletionProtectionCheck="BYPASS"
            )
        )
    )
    content = json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": False}},
            "version": "1",
        }
    ).encode("utf-8")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
    )["VersionNumber"]
    # DeleteConfigurationProfile hard-rejects (BadRequestException) while any hosted
    # configuration version still exists under it -- delete the version first. Registered
    # AFTER the profile's own cleanup so LIFO runs it BEFORE the profile delete.
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
            )
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
    # DeleteType defaults to ARCHIVE (a soft delete): the definition would keep existing and
    # keep blocking deletion of its configuration profile, environment and application. DESTROY
    # is what the in-body delete of def_id_a already uses; this mirrors it for the cleanup path.
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, DeleteType="DESTROY"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_delete(delete_call, timeout_s=20.0, interval_s=2.0):
    """Delete, treating not-found as clean; retry a refusal while a sibling delete from the same
    LIFO teardown is still being released, then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete_call()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("BadRequestException", "ConflictException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
