"""op-contract-listEnvironments."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-listEnvironments"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEnvironments returns every created environment with its state; a
    well-formed but nonexistent ApplicationId yields ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    # AppConfig refuses DeleteApplication while any environment survives, so the environments must
    # be torn down first. on_cleanup runs LIFO, so registering them after the application's cleanup
    # makes them run before it.
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env1_name = ctx.unique_name("sim2real-behav-env1-")
    env2_name = ctx.unique_name("sim2real-behav-env2-")
    env1_id = appconfig.create_environment(ApplicationId=app_id, Name=env1_name)["Id"]
    env2_id = appconfig.create_environment(ApplicationId=app_id, Name=env2_name)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env1_id))
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env2_id))

    # Newly created environments can take a while before ListEnvironments
    # (which can lag behind the authoritative per-resource state due to its
    # own eventual-consistency window) reports their steady-state ready
    # status, so poll with a generous bound rather than asserting on the
    # very first read.
    #
    # Note: despite the API documentation showing the enum as
    # READY_FOR_DEPLOYMENT, the actual wire value returned by the service is
    # the PascalCase "ReadyForDeployment" (confirmed against real AWS).
    by_id = _poll_until_ready(appconfig, app_id, (env1_id, env2_id), timeout_s=180.0, interval_s=5.0)
    items = list(by_id.values())
    assert len(items) == 2, f"expected exactly 2 environments, got {len(items)}"
    assert by_id[env1_id]["Name"] == env1_name, by_id[env1_id]
    assert by_id[env2_id]["Name"] == env2_name, by_id[env2_id]
    assert by_id[env1_id]["State"] == "ReadyForDeployment", by_id[env1_id]
    assert by_id[env2_id]["State"] == "ReadyForDeployment", by_id[env2_id]

    err = _error(lambda: appconfig.list_environments(ApplicationId="0000000"))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == f"Application with Id 0000000 could not be found for account {account}.", (
        f"unexpected message: {err['Message']!r}"
    )


def _poll_until_ready(appconfig, app_id, env_ids, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    by_id = {}
    while True:
        resp = appconfig.list_environments(ApplicationId=app_id)
        by_id = {item["Id"]: item for item in resp["Items"]}
        if all(by_id.get(eid, {}).get("State") == "ReadyForDeployment" for eid in env_ids):
            return by_id
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"environments {env_ids} did not reach ReadyForDeployment within "
                f"{timeout_s}s: {by_id!r}"
            )
        time.sleep(interval_s)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

