"""update-with-stale-version-id-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-with-stale-version-id-rejected"
GROUP = 'rejected-concurrent-modification'
SERVICES = ['kinesisanalyticsv2']

RUNTIME = "FLINK-1_15"

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "kinesisanalytics.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

def _error(fn) -> dict:
    """The AWS error (``Code`` and ``Message``) raised by ``fn``.

    Raises if the call SUCCEEDS: an emulator that accepts a stale version id is the defect this
    check exists to catch, and a sentinel return would turn it into a code mismatch.
    """
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if not response:
            raise
        return response["Error"]
    raise AssertionError("call unexpectedly SUCCEEDED where real AWS rejects it")


def _until_role_assumable(ctx, call, **kwargs) -> dict:
    """``call(**kwargs)``, retrying only the IAM-propagation refusal for up to 150 s.

    A role created seconds earlier is not yet assumable by the service, which reports
    `InvalidArgumentException: ... doesn't have sufficient privileges to assume the role`.
    """
    deadline = time.monotonic() + 150
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            return call(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "sufficient privileges to assume the role" not in msg:
                raise
            last = msg
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{call.__name__} never stopped reporting a non-assumable role: {last}")
        time.sleep(2)


def _delete_application(kda, app: str) -> None:
    detail = kda.describe_application(ApplicationName=app)["ApplicationDetail"]
    if detail["ApplicationStatus"] != "DELETING":
        kda.delete_application(ApplicationName=app, CreateTimestamp=detail["CreateTimestamp"])


def _parallelism(kda, app: str) -> dict:
    flink = kda.describe_application(ApplicationName=app)["ApplicationDetail"][
        "ApplicationConfigurationDescription"]["FlinkApplicationConfigurationDescription"]
    return flink["ParallelismConfigurationDescription"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An update quoting a consumed CurrentApplicationVersionId is refused, and changes nothing.

    The version pointer and configuration stay untouched, and the same update body quoting the
    current version id succeeds.
    """
    kda = ctx.client("kinesisanalyticsv2")
    iam = ctx.client("iam")

    app = ctx.unique_name("sim2real-behav-kdav2-")
    role_name = ctx.unique_name("sim2real-behav-kdav2-")

    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    created = _until_role_assumable(
        ctx, kda.create_application,
        ApplicationName=app,
        RuntimeEnvironment=RUNTIME,
        ServiceExecutionRole=role["Role"]["Arn"],
        ApplicationDescription="sim2real behavioral concurrency check",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_application(kda, app))
    assert created["ApplicationDetail"]["ApplicationVersionId"] == 1, (
        f"a newly created application is at version "
        f"{created['ApplicationDetail']['ApplicationVersionId']!r}, expected 1"
    )
    assert _parallelism(kda, app)["ConfigurationType"] == "DEFAULT", (
        f"a newly created application starts at parallelism configuration "
        f"{_parallelism(kda, app)['ConfigurationType']!r}, expected 'DEFAULT'"
    )

    first = _until_role_assumable(
        ctx, kda.update_application, ApplicationName=app, CurrentApplicationVersionId=1,
        ApplicationConfigurationUpdate={"FlinkApplicationConfigurationUpdate": {
            "ParallelismConfigurationUpdate": {
                "ConfigurationTypeUpdate": "CUSTOM", "ParallelismUpdate": 1,
                "ParallelismPerKPUUpdate": 1, "AutoScalingEnabledUpdate": False,
            }}})
    assert first["ApplicationDetail"]["ApplicationVersionId"] == 2, (
        f"the first update produced version "
        f"{first['ApplicationDetail']['ApplicationVersionId']!r}, expected 2"
    )

    # Break exactly one thing: replay the now-consumed version id.
    stale = _error(lambda: kda.update_application(
        ApplicationName=app, CurrentApplicationVersionId=1,
        ApplicationConfigurationUpdate={"FlinkApplicationConfigurationUpdate": {
            "ParallelismConfigurationUpdate": {"ConfigurationTypeUpdate": "DEFAULT"}}}))
    assert stale["Code"] == "ConcurrentModificationException", (
        f"an update quoting the consumed version id 1 was refused with {stale['Code']!r}, "
        f"expected 'ConcurrentModificationException'"
    )
    expected = (
        "The provided application version ID does not match the most recent version for the "
        "application."
    )
    assert stale["Message"] == expected, (
        f"an update quoting the consumed version id 1 was refused with message "
        f"{stale['Message']!r}, expected {expected!r}"
    )

    after = _parallelism(kda, app)
    assert after["ConfigurationType"] == "CUSTOM", (
        f"the refused update reverted the parallelism configuration to "
        f"{after['ConfigurationType']!r}; version 2's 'CUSTOM' must survive"
    )
    assert after["AutoScalingEnabled"] is False, (
        f"the refused update re-enabled autoscaling ({after['AutoScalingEnabled']!r})"
    )
    detail = kda.describe_application(ApplicationName=app)["ApplicationDetail"]
    assert detail["ApplicationVersionId"] == 2, (
        f"the refused update moved the version pointer to "
        f"{detail['ApplicationVersionId']!r}, expected it to stay at 2"
    )

    # Positive control: the same body, quoting the current version id.
    ok = kda.update_application(
        ApplicationName=app, CurrentApplicationVersionId=2,
        ApplicationConfigurationUpdate={"FlinkApplicationConfigurationUpdate": {
            "ParallelismConfigurationUpdate": {"ConfigurationTypeUpdate": "DEFAULT"}}})
    assert ok["ApplicationDetail"]["ApplicationVersionId"] == 3, (
        f"the update quoting the current version id produced version "
        f"{ok['ApplicationDetail']['ApplicationVersionId']!r}, expected 3"
    )
    assert _parallelism(kda, app)["ConfigurationType"] == "DEFAULT", (
        f"the accepted update left the parallelism configuration at "
        f"{_parallelism(kda, app)['ConfigurationType']!r}, expected 'DEFAULT'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
