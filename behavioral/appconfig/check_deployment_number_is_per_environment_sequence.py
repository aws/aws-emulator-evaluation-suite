"""deployment-number-is-per-environment-sequence."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-number-is-per-environment-sequence"
GROUP = 'deployment'
SERVICES = ['appconfig']

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90, interval_s=2.0, description="condition"):
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

    Every page is read: AppConfig refuses a parent delete while any child survives.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _drain_and_delete_app(ac, app_id, timeout_s=180):
    """Stop in-flight deployments, wait environments out of transitional states, delete the
    application, and confirm it is gone. Raises rather than leaking silently."""
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        env_id = env["Id"]
        # Per environment, NOT one budget for the whole purge, so earlier waits cannot starve it.
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id,
                EnvironmentId=env_id,
            )
        ):
            if dep.get("State") in _DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
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
    # Children first: AppConfig refuses DeleteApplication while children exist and
    # DeleteConfigurationProfile while hosted versions exist.
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(
            ApplicationId=app_id,
        )
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)
    # Its own budget as well, independent of the environment waits above.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ac.get_application(ApplicationId=app_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise AssertionError(
                f"unexpected error confirming application deletion: {code!r}"
            ) from exc
        time.sleep(1.0)
    raise AssertionError(f"application {app_id} still present after the cleanup deadline")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeploymentNumber is scoped per (application, environment): two environments each start at 1
    and advance independently, ListDeployments stays per environment, and GetDeployment under the
    wrong environment is a 404 even though that number exists in the sibling."""
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    env_a = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-a-")
    )["Id"]
    env_b = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-b-")
    )["Id"]
    assert env_a != env_b, f"two CreateEnvironment calls returned the same id: {env_a!r}"

    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-cp-"), LocationUri="hosted"
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    # Deployment strategy is deleted LAST (after the app + its in-flight deployments are
    # drained/gone): register its cleanup first so LIFO runs it after the drain-app cleanup.
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    ctx.on_cleanup(lambda: _drain_and_delete_app(ac, app_id))

    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"seq":1}',
        ContentType="application/json",
    )["VersionNumber"]
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"seq":2}',
        ContentType="application/json",
    )["VersionNumber"]

    def _start(env_id, version):
        return ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(version),
        )

    # --- Both environments' FIRST deployment must be number 1. No wait is needed: the
    # numbering is decided synchronously by StartDeployment.
    a1 = _start(env_a, v1)
    b1 = _start(env_b, v1)
    assert a1["DeploymentNumber"] == 1, (
        f"environment A's first deployment must be 1, got {a1['DeploymentNumber']} — a "
        f"value other than 1 means the counter is not scoped to the environment"
    )
    assert b1["DeploymentNumber"] == 1, (
        f"environment B's first deployment must also be 1, got {b1['DeploymentNumber']} — "
        f"2 would mean a per-application (or global) counter"
    )
    assert a1["EnvironmentId"] == env_a, a1["EnvironmentId"]
    assert b1["EnvironmentId"] == env_b, b1["EnvironmentId"]

    # --- Advance environment A only. AppConfig serialises deployments within an environment,
    # so A's first deployment must finish before its second can start.
    _poll_until(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_a, DeploymentNumber=1
        ),
        lambda d: d.get("State") in _DEPLOYMENT_TERMINAL,
        timeout_s=90,
        interval_s=2.0,
        description="environment A deployment 1 reaching a terminal state",
    )
    a2 = _start(env_a, v2)
    assert a2["DeploymentNumber"] == 2, (
        f"environment A's second deployment must be 2, got {a2['DeploymentNumber']}"
    )

    # --- Listings are scoped, and each is ordered by its own sequence.
    a_numbers = sorted(
        d["DeploymentNumber"]
        for d in ac.list_deployments(ApplicationId=app_id, EnvironmentId=env_a)["Items"]
    )
    b_numbers = sorted(
        d["DeploymentNumber"]
        for d in ac.list_deployments(ApplicationId=app_id, EnvironmentId=env_b)["Items"]
    )
    assert a_numbers == [1, 2], (
        f"ListDeployments for environment A must return exactly [1, 2], got {a_numbers}"
    )
    assert b_numbers == [1], (
        f"ListDeployments for environment B must return exactly [1] — environment A's "
        f"deployments must not leak in; got {b_numbers}"
    )

    # --- The same number in the two environments is two different deployments.
    a_one = ac.get_deployment(ApplicationId=app_id, EnvironmentId=env_a, DeploymentNumber=1)
    b_one = ac.get_deployment(ApplicationId=app_id, EnvironmentId=env_b, DeploymentNumber=1)
    assert a_one["EnvironmentId"] == env_a, a_one["EnvironmentId"]
    assert b_one["EnvironmentId"] == env_b, b_one["EnvironmentId"]
    assert a_one["DeploymentNumber"] == b_one["DeploymentNumber"] == 1, (
        a_one["DeploymentNumber"],
        b_one["DeploymentNumber"],
    )

    # --- Negative: deployment 2 exists in A and does NOT exist in B. Addressing it under B
    # must be a 404, not A's record.
    code, message = _client_error(
        lambda: ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_b, DeploymentNumber=2
        )
    )
    assert code == "ResourceNotFoundException", (
        f"GetDeployment(env=B, number=2) must be ResourceNotFoundException — deployment 2 "
        f"belongs to environment A only; got {code!r}"
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected = (
        f"Deployment with Application Id {app_id}, Environment Id {env_b}, and deploymentNumber 2 "
        f"could not be found for account {account_id}."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # --- The control still works: the identical number under the right environment is 200.
    a_two = ac.get_deployment(ApplicationId=app_id, EnvironmentId=env_a, DeploymentNumber=2)
    assert a_two["EnvironmentId"] == env_a, a_two["EnvironmentId"]
    assert a_two["ConfigurationVersion"] == str(v2), a_two["ConfigurationVersion"]
    assert a_one["ConfigurationVersion"] == str(v1), a_one["ConfigurationVersion"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
