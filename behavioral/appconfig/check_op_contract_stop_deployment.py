"""op-contract-stopDeployment."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "op-contract-stopDeployment"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-op-contract-stop-deployment"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopDeployment moves an in-progress deployment to ROLLING_BACK then ROLLED_BACK, keeping
    StartedAt and a sub-100% completion with no CompletedAt; a nonexistent DeploymentNumber raises
    ResourceNotFoundException.
    """
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    # AppConfig refuses DeleteApplication while any child (environment, configuration profile,
    # hosted version) survives; registering the children's cleanups after the application's makes
    # the LIFO teardown delete them first.
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    )
    version = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"flag":true}',
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version
        )
    )

    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strat-"),
        DeploymentDurationInMinutes=2,
        GrowthFactor=5,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]

    stopped = appconfig.stop_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
    )
    assert stopped["State"] in ("ROLLING_BACK", "ROLLED_BACK"), f"unexpected state: {stopped['State']}"

    final_state = _poll_terminal(appconfig, app_id, env_id, deployment_number, timeout_s=90.0)
    assert final_state == "ROLLED_BACK", f"expected ROLLED_BACK, got {final_state}"
    # A deployment that is aborted via StopDeployment never reaches the
    # "naturally completed" milestone, so unlike a COMPLETE deployment it
    # does not get a CompletedAt timestamp stamped on it (confirmed against
    # real AWS: CompletedAt stays unset indefinitely once terminal in the
    # ROLLED_BACK state). StartedAt, however, is still populated and the
    # rollback must not be reported as fully complete.
    final = appconfig.get_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
    )
    assert final["State"] == "ROLLED_BACK", final
    assert final.get("StartedAt") is not None, "StartedAt must be set once the deployment has run"
    assert final.get("CompletedAt") is None, "a rolled-back deployment must not report a completion time"
    assert final["PercentageComplete"] < 100.0, "a stopped deployment must not report full completion"

    code, message = _error_of(
        lambda: appconfig.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=999
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # AWS appends an internal backend error code and request id that differ per call: mask only those.
    assert re.sub(
        r"Error Code: [^;]*; Request ID: [0-9a-f-]+;", "Error Code: <code>; Request ID: <id>;", message
    ) == (
        f"Deployment with Application Id {app_id}, Environment Id {env_id}, and deploymentNumber 999 "
        f"could not be found for account {ctx.account}. (Service: AWSAppConfigData; Status Code: 404; "
        "Error Code: <code>; Request ID: <id>; Proxy: null)"
    ), f"ResourceNotFoundException message {message!r}"


def _error_of(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    raise AssertionError(f"deployment did not reach a terminal state within {timeout_s}s; last saw {state!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
