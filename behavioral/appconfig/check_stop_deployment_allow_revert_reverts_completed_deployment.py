"""stop-deployment-allow-revert-reverts-completed-deployment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "stop-deployment-allow-revert-reverts-completed-deployment"
GROUP = 'deployment'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-stop-allow-revert"}
_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")

# _drain_and_delete_app polls each environment to a deletable state, deletes bottom-up, polls the
# application to disappearance and raises on a deadline miss, so a stuck environment never leaks.


def _error(fn):
    """Call fn(); return its botocore Error (Code and Message). An unexpected SUCCESS raises,
    so an over-permissive target fails as a success rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Teardown reads every page, not just the first: AppConfig refuses a parent delete while any child
    survives, so a first-page-only purge would leak the tree.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _drain_and_delete_app(ac, app_id, timeout_s=180):
    """Stop every in-flight deployment, wait each environment out of a transitional state,
    delete the application's whole tree bottom-up, and confirm the application is gone. Raises
    if cleanup cannot complete."""
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        env_id = env["Id"]
        # Per environment, not one budget for the whole purge: each environment gets the full wait.
        deadline = time.monotonic() + timeout_s
        deployments = _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id,
                EnvironmentId=env_id,
            )
        )
        for dep in deployments:
            if dep.get("State") in _DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                # The only tolerated failure: it reached a terminal state between the
                # list and the stop, which AppConfig reports as BadRequestException.
                if exc.response.get("Error", {}).get("Code") != "BadRequestException":
                    raise
        while time.monotonic() < deadline:
            if ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get(
                "State"
            ) not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(
                f"environment {env_id} never left {_ENV_TRANSITIONAL} during cleanup"
            )

    # AppConfig gates deletion on CHILD EXISTENCE: DeleteApplication answers BadRequestException
    # "Cannot delete application <id>, because there are still environments existing under it." (and
    # likewise "... configuration profiles existing under it."), and DeleteConfigurationProfile
    # answers "Cannot delete configuration profile <id> because there are still hosted configuration
    # versions existing under it." So teardown MUST run bottom-up — hosted versions, then profiles,
    # then environments, then the application — or the cleanup silently leaks the whole tree.
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(
            ApplicationId=app_id,
        )
    ):
        cp = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id,
                ConfigurationProfileId=cp,
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp, DeletionProtectionCheck="BYPASS"
        )
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )

    ac.delete_application(ApplicationId=app_id)
    # Its own budget as well, for the same reason: confirming the application is gone must not
    # inherit whatever the environment waits above happened to leave.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ac.get_application(ApplicationId=app_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            raise AssertionError(f"unexpected error confirming application deletion: {code!r}")
        time.sleep(1.0)
    raise AssertionError(f"application {app_id} still present after the cleanup deadline")


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=90):
    """Start a deployment and poll until it is COMPLETE. Deliberately NOT tolerant: the
    three sibling data-plane helpers accept ("COMPLETE","ROLLED_BACK","REVERTED") as a
    successful setup, which lets a rolled-back deployment pass as a deployed one."""
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]
    final = _poll_until(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        ),
        lambda d: d.get("State") in _DEPLOYMENT_TERMINAL,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"deployment {dep_num} reaching a terminal state",
    )
    assert final["State"] == "COMPLETE", (
        f"deployment {dep_num} of version {version} terminated in {final['State']!r}, "
        f"not COMPLETE"
    )
    return dep_num


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopDeployment on a COMPLETE deployment is refused, while AllowRevert=True drives it to
    REVERTED (the environment settles on "Reverted") and the data plane serves the previous version
    again: the only way to undo a completed release.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v1_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v2_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert (v1, v2) == (1, 2), f"hosted version numbering: got {v1!r}, {v2!r}"

    # --- Full valid setup: v1 then v2, both driven to COMPLETE.
    dep1 = _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v1)
    dep2 = _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v2)
    assert dep2 == dep1 + 1, f"deployment numbers must increment: {dep1} then {dep2}"

    # A COMPLETE deployment leaves the environment ready again (CamelCase, not the
    # SCREAMING_SNAKE the Smithy @enumValue documents).
    assert (
        ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
        == "ReadyForDeployment"
    ), ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]

    # --- Break exactly one thing: stop a COMPLETE deployment WITHOUT AllowRevert.
    err = _error(
        lambda: ac.stop_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )
    )
    # Pinned as one value on purpose: a tuple would let an emulator that refuses for the wrong
    # reason pass.
    assert err["Code"] == "BadRequestException", (
        f"StopDeployment without AllowRevert on a COMPLETE deployment must be refused "
        f"with BadRequestException, got {err['Code']!r} — an emulator that accepts this is "
        f"over-permissive on the deployment state machine"
    )
    assert err["Message"] == (
        f"Deployment {dep2} for App {app_id} and Environment {env_id} cannot be stopped, "
        "it has a status of COMPLETE."
    ), f"unexpected message: {err['Message']!r}"

    # --- Effect absent: the refused call changed nothing.
    still = ac.get_deployment(
        ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
    )
    assert still["State"] == "COMPLETE", (
        f"a refused StopDeployment must not mutate the deployment; state is "
        f"{still['State']!r}"
    )
    assert still["ConfigurationVersion"] == str(v2), still["ConfigurationVersion"]
    assert (
        ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
        == "ReadyForDeployment"
    ), "a refused StopDeployment must not move the environment out of ReadyForDeployment"

    # --- The control case still works: the same call WITH AllowRevert is accepted.
    # The synchronous response state IS asserted: AWS answers State="REVERTED" with
    # PercentageComplete=0.0 in the StopDeployment response itself — the revert of a 0-minute/0-bake
    # deployment is already terminal when the call returns. It does NOT report the unmodeled
    # "REVERTING" that the sibling second-stop check tolerates ("REVERTING" is absent from the
    # DeploymentState enum in both the Smithy model and botocore 1.43.36: BAKING, VALIDATING,
    # DEPLOYING, COMPLETE, ROLLING_BACK, ROLLED_BACK, REVERTED).
    stop_resp = ac.stop_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentNumber=dep2,
        AllowRevert=True,
    )
    assert stop_resp["State"] == "REVERTED", (
        f"StopDeployment(AllowRevert=True) on a COMPLETE deployment must answer State="
        f"'REVERTED' synchronously, got {stop_resp['State']!r} — 'REVERTING' is not a member of "
        f"the DeploymentState enum, and 'ROLLED_BACK' would conflate revert with rollback"
    )
    reverted = _poll_until(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        ),
        lambda d: d.get("State") in _DEPLOYMENT_TERMINAL,
        timeout_s=60,
        interval_s=2.0,
        description="reverted deployment reaching a terminal state",
    )
    assert reverted["State"] == "REVERTED", (
        f"AllowRevert=True must terminate the deployment as REVERTED, got "
        f"{reverted['State']!r} — ROLLED_BACK would mean the emulator conflates revert "
        f"with rollback"
    )
    # A reverted environment does NOT go back to ReadyForDeployment. VERIFIED: it reports
    # "Reverted" immediately after the stop and still reports "Reverted" 120s later, so this is
    # the environment's settled state and not a transient. Asserted exactly, in the CamelCase
    # the API actually emits, against the SCREAMING_SNAKE "REVERTED" of the deployment above.
    env_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
    assert env_state == "Reverted", (
        f"a reverted environment must report State='Reverted' (the CamelCase rendering of the "
        f"modeled EnvironmentState member REVERTED), got {env_state!r}; 'ReadyForDeployment' "
        f"would mean the emulator treats a revert as a completed deployment, and 'REVERTED' "
        f"would mean it serves the modeled casing instead of the wire casing"
    )
    assert env_state != reverted["State"], (
        f"the casing asymmetry is the point: GetEnvironment reports {env_state!r} while "
        f"GetDeployment reports {reverted['State']!r} for the same revert"
    )
    # Freeze detector, not a single dwell: the claim is that Reverted is TERMINAL, so the only
    # way to observe that is repeated reads spaced over a window, each one demanded to still say
    # Reverted -- a target that transiently reports it then drifts back fails on the first
    # deviating read instead of only after one final sleep.
    for i in range(5):
        time.sleep(2.0)
        env_state_now = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
        assert env_state_now == "Reverted", (
            f"'Reverted' is a settled environment state, not a transient on the way back to "
            f"ReadyForDeployment (real AWS still reported it 120s after the revert); it became "
            f"{env_state_now!r} on read {i + 1}/5 of the post-revert window"
        )

    # --- The revert is real on the data plane: v1 is served again, not v2.
    token = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
        RequiredMinimumPollIntervalInSeconds=15,
    )["InitialConfigurationToken"]
    served = _poll_until(
        lambda: acd.get_latest_configuration(ConfigurationToken=token)[
            "Configuration"
        ].read(),
        lambda body: body == v1_bytes,
        timeout_s=60,
        interval_s=15.0,
        description="reverted configuration (v1) served on the data plane",
    )
    assert served == v1_bytes, served
    assert served != v2_bytes, "the data plane is still serving the reverted-away version"

    # --- Reverting an already-REVERTED deployment is refused, and nothing changes.
    err2 = _error(
        lambda: ac.stop_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentNumber=dep2,
            AllowRevert=True,
        )
    )
    assert err2["Code"] == "BadRequestException", (
        f"a second AllowRevert stop on a REVERTED deployment must be refused, got {err2['Code']!r}"
    )
    assert err2["Message"] == (
        f"Deployment {dep2} for App {app_id} and Environment {env_id} cannot be reverted, "
        "it has a status of REVERTED."
    ), f"unexpected message: {err2['Message']!r}"
    assert (
        ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )["State"]
        == "REVERTED"
    ), "the refused second revert must leave the deployment REVERTED"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
