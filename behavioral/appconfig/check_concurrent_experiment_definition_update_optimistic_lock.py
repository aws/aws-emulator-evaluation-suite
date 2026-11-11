"""concurrent-experiment-definition-update-optimistic-lock."""
from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-experiment-definition-update-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateExperimentDefinition calls replacing disjoint bundles of Hypothesis and LaunchCriteria
    never leave a definition that mixes both callers' fields, and any racer that fails gets ConflictException;
    the API has no version parameter, so per-update atomicity is the invariant under test."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    flag_key = f"flag{uuid.uuid4().hex[:8]}"
    profile_id = _create_feature_flag_profile(ctx, app_id, flag_key)
    def_id = _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key)

    bundle_a = {"Hypothesis": "hyp-A", "LaunchCriteria": "crit-A"}
    bundle_b = {"Hypothesis": "hyp-B", "LaunchCriteria": "crit-B"}

    def _update(bundle):
        return appconfig.update_experiment_definition(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id, **bundle
        )

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, bundle_a), pool.submit(_update, bundle_b)]
        for f in futures:
            try:
                results.append(("ok", f.result()))
            except ClientError as e:
                err = e.response["Error"]
                results.append(("err", err["Code"], err.get("Message")))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]
    assert len(successes) >= 1, "expected at least one concurrent update to succeed"
    for _, err_code, err_message in failures:
        # message varies: AWS applies both racing updates, so ConflictException is not
        # observed and no message can be pinned.
        assert err_code == "ConflictException", (
            f"expected ConflictException, got {err_code}: {err_message!r}"
        )

    final = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=def_id
    )
    matches_a = final["Hypothesis"] == bundle_a["Hypothesis"] and final["LaunchCriteria"] == bundle_a["LaunchCriteria"]
    matches_b = final["Hypothesis"] == bundle_b["Hypothesis"] and final["LaunchCriteria"] == bundle_b["LaunchCriteria"]
    assert matches_a or matches_b, (
        "final state mixed fields from both concurrent callers: "
        f"Hypothesis={final['Hypothesis']!r} LaunchCriteria={final['LaunchCriteria']!r}"
    )


_PREFIX = "sim2real-appconfig-"
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-experiment-definition-update"}


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name(_PREFIX + "app-"), Tags=_TAGS)["Id"]

    def _cleanup():
        try:
            appconfig.delete_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name(_PREFIX + "env-"), Tags=_TAGS
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return env_id


def _create_feature_flag_profile(ctx, app_id, flag_key):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name(_PREFIX + "profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_configuration_profile(
                ApplicationId=app_id, ConfigurationProfileId=profile_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

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

    def _cleanup_version():
        try:
            appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_version)
    return profile_id


def _create_experiment_definition(ctx, app_id, profile_id, env_id, flag_key):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_experiment_definition(
        ApplicationIdentifier=app_id,
        Name=ctx.unique_name(_PREFIX + "expdef-"),
        ConfigurationProfileIdentifier=profile_id,
        EnvironmentIdentifier=env_id,
        FlagKey=flag_key,
        Treatments=[{"Weight": 50.0, "FlagValue": {"Enabled": True}}],
        Control={"Weight": 50.0, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    def_id = resp["Id"]

    def _cleanup():
        try:
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=app_id,
                ExperimentDefinitionIdentifier=def_id,
                DeleteType="DESTROY",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return def_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
