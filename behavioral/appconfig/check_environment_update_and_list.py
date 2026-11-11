"""environment-update-and-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-update-and-list"
GROUP = "environment"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironment mutations are visible in both GetEnvironment and ListEnvironments."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-app-"),
        Tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    created = appconfig.create_environment(
        ApplicationId=app_id,
        Name="env-v1",
        Description="first",
        Tags={"sim2real:managed": "true", "sim2real": CHECK},
    )
    env_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_environment(appconfig, app_id, env_id))

    # Environment provisioning settles asynchronously on real AWS -- poll for the initial ready
    # state instead of asserting on the (possibly not-yet-settled) create response. Note: despite
    # the API documentation showing the enum as READY_FOR_DEPLOYMENT, the actual wire value returned
    # by the service is the PascalCase "ReadyForDeployment".
    initial_state = _poll_until(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"],
        lambda state: state == "ReadyForDeployment",
        timeout_s=30.0,
        interval_s=2.0,
        description="environment ready state",
    )
    assert initial_state == "ReadyForDeployment", f"expected ready state, got {initial_state}"

    got = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got["Name"] == "env-v1"
    assert got["Description"] == "first"
    assert got["State"] == "ReadyForDeployment"

    updated = appconfig.update_environment(
        ApplicationId=app_id, EnvironmentId=env_id, Name="env-v2", Description="second"
    )
    assert updated["Name"] == "env-v2"
    assert updated["Description"] == "second"
    assert updated["State"] == "ReadyForDeployment", "updating Name/Description must not change the ready state"

    got2 = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got2["Name"] == "env-v2"
    assert got2["Description"] == "second"
    assert got2["State"] == "ReadyForDeployment"

    items = _list_all_environments(appconfig, app_id)
    match = next((i for i in items if i["Id"] == env_id), None)
    assert match is not None, "environment not found in ListEnvironments"
    assert match["Name"] == "env-v2"
    assert match["Description"] == "second"
    assert match["State"] == "ReadyForDeployment"

    appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)

    items_after = _list_all_environments(appconfig, app_id)
    assert all(i["Id"] != env_id for i in items_after), "deleted environment still listed"

    err = _error(lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {err['Code']}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == (
        f"Environment with Application Id {app_id} and Environment Id {env_id} "
        f"could not be found for account {account}."
    ), f"unexpected message: {err['Message']!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_environment(appconfig, app_id, env_id):
    try:
        appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_environments(appconfig, app_id):
    items = []
    kwargs = {"ApplicationId": app_id}
    while True:
        resp = appconfig.list_environments(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"ApplicationId": app_id, "NextToken": token}
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
