"""concurrent-start-experiment-run-conflict."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-start-experiment-run-conflict"
GROUP = "concurrency"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent StartExperimentRun calls against the same ExperimentDefinition must
    resolve to exactly one RUNNING run; every other racer gets ConflictException, and no
    experiment definition ever has two concurrently-active runs."""
    appconfig = ctx.client("appconfig")
    base = _setup_experiment_base(ctx)
    created = _create_experiment_definition(ctx, appconfig, base)
    def_id = created["Id"]

    n_racers = 6

    def _start():
        try:
            resp = appconfig.start_experiment_run(
                ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
            )
            return ("ok", resp["Run"])
        except Exception as e:
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("err", (e.response["Error"]["Code"], e.response["Error"]["Message"]))
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_start) for _ in range(n_racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for kind, r in results if kind == "ok"]
    failures = [r for kind, r in results if kind == "err"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} rejected racers, got {len(failures)}: {results}"
    )
    for code, message in failures:
        assert code == "ConflictException", (
            f"expected every loser to fail with ConflictException, got {failures}"
        )
        expected = _conflict_message(def_id, message)
        assert message == expected, (
            f"expected every loser to carry an exact StartExperimentRun conflict message, got {failures}"
        )

    # There must be exactly one RUNNING run visible for this definition.
    runs = appconfig.list_experiment_runs(
        ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
    )["Items"]
    running = [r for r in runs if r["Status"] == "RUNNING"]
    assert len(running) == 1, f"expected exactly 1 RUNNING run visible, got {running}"
    assert running[0]["Run"] == successes[0], (
        f"the visible RUNNING run {running[0]['Run']!r} does not match the winner {successes[0]!r}"
    )


_IN_FLIGHT = "A previous operation for run 1 is in flight, retry in "


def _conflict_message(def_id, message):
    """The StartExperimentRun conflict text a loser carries; which one depends on how far the winner
    got, and the in-flight one ends in a retry interval AWS chooses, so that number is read back."""
    if message.startswith(_IN_FLIGHT):
        seconds = message.removeprefix(_IN_FLIGHT).removesuffix("s.")
        return f"{_IN_FLIGHT}{seconds if seconds.isdigit() else '<seconds>'}s."
    if message.startswith("Experiment run number "):
        return f"Experiment run number 1 already exists for experiment definition {def_id}"
    return (
        f"Experiment definition {def_id} already has a running experiment. The current experiment run "
        "must be stopped before a run can be started."
    )


_AUDIENCE_RULE = '(eq $country "US")'
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-start-experiment-run-conflict"}


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
    # A profile refuses deletion while hosted versions exist, so this teardown runs first.
    ctx.on_cleanup(lambda: _delete_hosted_version(appconfig, app_id, profile_id, version_number))

    # Experiments require an existing deployment of the flag to the environment. Use a
    # custom zero-bake-time strategy so the deployment reaches COMPLETE quickly instead of
    # sitting in the 10-minute default bake window of the predefined AllAtOnce strategy.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        GrowthType="LINEAR",
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    deployment = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment["DeploymentNumber"])

    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


def _wait_for_deployment_complete(
    appconfig, app_id, env_id, deployment_number, timeout_s=240.0, interval_s=5.0
):
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last = None
    while _time.monotonic() < deadline:
        last = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if last["State"] == "COMPLETE":
            return last
        if last["State"] in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment failed: {last}")
        _time.sleep(interval_s)
    raise AssertionError(f"deployment not complete within {timeout_s}s; last={last!r}")


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

    def _cleanup():
        try:
            for r in appconfig.list_experiment_runs(
                ApplicationIdentifier=base["app_id"], ExperimentDefinitionIdentifier=def_id
            ).get("Items", []):
                if r.get("Status") == "RUNNING":
                    try:
                        appconfig.stop_experiment_run(
                            ApplicationIdentifier=base["app_id"],
                            ExperimentDefinitionIdentifier=def_id,
                            Run=r["Run"],
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
            appconfig.delete_experiment_definition(
                ApplicationIdentifier=base["app_id"],
                ExperimentDefinitionIdentifier=def_id,
                DeleteType="DESTROY",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return resp


def _delete_hosted_version(appconfig, app_id, profile_id, version_number):
    """Teardown DeleteHostedConfigurationVersion; ResourceNotFoundException is already gone."""
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
