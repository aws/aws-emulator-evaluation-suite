"""update-environment-state-and-monitors-persist."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-environment-state-and-monitors-persist"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironment persists Monitors/Description changes without altering the ready state."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    created = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )
    env_id = created["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    # Environment provisioning settles asynchronously on real AWS; poll for the initial
    # ready state instead of asserting on the (possibly not-yet-settled) create response.
    # Note: despite the API documentation showing the enum as READY_FOR_DEPLOYMENT, the
    # actual wire value returned by the service is the PascalCase "ReadyForDeployment".
    initial_state = _poll_until(
        lambda: appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"],
        lambda state: state == "ReadyForDeployment",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert initial_state == "ReadyForDeployment", f"expected ready state, got {initial_state}"
    assert created.get("Monitors", []) == [], f"expected no monitors on creation, got {created.get('Monitors')!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:alarm:{ctx.unique_name('sim2real-alarm-')}"
    # Real AWS requires AlarmRoleArn to be supplied alongside AlarmArn (it is not implicitly
    # defaulted to a service-linked role); omitting it fails with a BadRequestException
    # complaining that 'alarmRoleArn' is null. Only the ARN's shape is validated at
    # Create/Update time (the same way an alarm that doesn't actually exist is accepted for
    # AlarmArn), so a well-formed role ARN is sufficient here.
    alarm_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-alarm-role-')}"

    updated = appconfig.update_environment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        Description="now monitored",
        Monitors=[{"AlarmArn": alarm_arn, "AlarmRoleArn": alarm_role_arn}],
    )
    assert updated["Description"] == "now monitored", f"expected updated description, got {updated['Description']!r}"
    assert len(updated["Monitors"]) == 1, f"expected exactly 1 monitor, got {updated['Monitors']!r}"
    assert updated["Monitors"][0]["AlarmArn"] == alarm_arn, (
        f"expected AlarmArn {alarm_arn!r}, got {updated['Monitors'][0]['AlarmArn']!r}"
    )
    assert updated["Monitors"][0]["AlarmRoleArn"] == alarm_role_arn, (
        f"expected AlarmRoleArn {alarm_role_arn!r}, got {updated['Monitors'][0]['AlarmRoleArn']!r}"
    )
    assert updated["State"] == "ReadyForDeployment", "adding a monitor must not change the ready state"

    got = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got["Description"] == "now monitored", f"expected persisted description, got {got['Description']!r}"
    assert len(got["Monitors"]) == 1, f"expected exactly 1 persisted monitor, got {got['Monitors']!r}"
    assert got["Monitors"][0]["AlarmArn"] == alarm_arn, (
        f"expected persisted AlarmArn {alarm_arn!r}, got {got['Monitors'][0]['AlarmArn']!r}"
    )
    assert got["Monitors"][0]["AlarmRoleArn"] == alarm_role_arn, (
        f"expected persisted AlarmRoleArn {alarm_role_arn!r}, got {got['Monitors'][0]['AlarmRoleArn']!r}"
    )
    assert got["State"] == "ReadyForDeployment", f"expected ready state to persist, got {got['State']!r}"


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
