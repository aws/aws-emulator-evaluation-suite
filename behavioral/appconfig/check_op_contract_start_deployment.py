"""op-contract-startDeployment."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-startDeployment"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartDeployment creates a numbered in-progress deployment echoing its strategy and version;
    a second start on the same environment meanwhile is a ConflictException that adds no
    deployment, and succeeds once the first is stopped."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-")
    )["Id"]

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
    )["Id"]
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"flag":true}',
        ContentType="application/json",
    )["VersionNumber"]

    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=1,
        GrowthFactor=10,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]

    deployment_numbers: list[int] = []

    def _cleanup():
        # Stop only a non-terminal deployment (a terminal one cannot be stopped) and wait it out;
        # delete bottom-up: AppConfig refuses DeleteApplication and DeleteConfigurationProfile
        # while a child exists.
        ids = {"ApplicationId": app_id, "EnvironmentId": env_id}
        for number in deployment_numbers:
            state = appconfig.get_deployment(DeploymentNumber=number, **ids)["State"]
            if state not in ("COMPLETE", "ROLLED_BACK", "REVERTED"):
                appconfig.stop_deployment(DeploymentNumber=number, **ids)
                _poll_terminal(appconfig, app_id, env_id, number, timeout_s=60.0)
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version
        )
        appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
        appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
        appconfig.delete_application(ApplicationId=app_id)
        appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)

    ctx.on_cleanup(_cleanup)

    started = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Description="behavioral-check",
    )
    deployment_numbers.append(started["DeploymentNumber"])
    assert started["DeploymentNumber"] == 1, "first deployment must be numbered 1"
    assert started["GrowthFactor"] == 10.0, f"expected echoed GrowthFactor 10.0, got {started['GrowthFactor']!r}"
    assert started["ConfigurationVersion"] == str(version), (
        f"expected echoed ConfigurationVersion {version!r}, got {started['ConfigurationVersion']!r}"
    )
    non_terminal = {"BAKING", "VALIDATING", "DEPLOYING"}
    assert started["State"] in non_terminal, f"unexpected initial state: {started['State']}"

    err = _error(
        lambda: appconfig.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=strategy_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(version),
        )
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']}"
    assert err["Message"] == (
        f"Environment {env_id} currently has a state of DEPLOYING. The current deployment must "
        f"finish before a new deployment can be started."
    ), f"unexpected message: {err['Message']!r}"

    # positive control: environment still reports exactly one deployment, unaffected by the conflict
    deployments = appconfig.list_deployments(ApplicationId=app_id, EnvironmentId=env_id)["Items"]
    assert len(deployments) == 1, f"conflicting call must not create a second deployment: {deployments}"

    # restore: stop the in-flight deployment, wait for it to actually reach a terminal state
    # (StopDeployment only acknowledges synchronously with a rollback/revert state — the
    # transition itself is asynchronous), then the identical call must now succeed.
    appconfig.stop_deployment(ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=1)
    _poll_terminal(appconfig, app_id, env_id, 1, timeout_s=90.0)

    restarted = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
    )
    deployment_numbers.append(restarted["DeploymentNumber"])
    assert restarted["DeploymentNumber"] == 2, (
        f"once the conflicting deployment is stopped the identical call must succeed, got {restarted}"
    )

    deployments_after_restore = appconfig.list_deployments(ApplicationId=app_id, EnvironmentId=env_id)["Items"]
    assert len(deployments_after_restore) == 2, (
        f"restored deployment must be visible alongside the first: {deployments_after_restore}"
    )


# ===== helpers =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_terminal(appconfig, app_id, env_id, deployment_number, timeout_s=90.0, interval_s=3.0):
    terminal = {"COMPLETE", "ROLLED_BACK", "REVERTED"}
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"deployment {deployment_number} did not reach a terminal state within {timeout_s}s: last={state}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
