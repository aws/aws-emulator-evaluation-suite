"""cloudwatch-alarm-rollback-restores-previous-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-rollback-restores-previous-version"
GROUP = 'deployment'
SERVICES = ['appconfig', 'cloudwatch']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-alarm-rollback"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_BAKE_MINUTES = 1  # the shortest non-zero bake; a bake window is needed for AppConfig to consult the monitor
_NAMESPACE = "sim2real/AppConfigRollback"
# Two baked deployments plus role-propagation retries need more than 300s.
_MONITOR_READY_TIMEOUT_S = 900
_ROLLBACK_TIMEOUT_S = 600

# Deletion protection may be on for the account, so deletes pass DeletionProtectionCheck="BYPASS".


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=300):
    """Delete an application and everything beneath it, bottom-up. Raises rather than leaking."""
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        ):
            if dep.get("State") in _TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException",
                    "ResourceNotFoundException",
                ):
                    raise
        state = None
        while time.monotonic() < deadline:
            state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
            if state not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(f"environment {env_id} never left {state!r} during cleanup")
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            DeletionProtectionCheck="BYPASS",
        )
    for env in _purge_items(
        ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
    ):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll fresh configuration sessions until one serves exactly `expect`; return the last payload.

    The data plane lags a COMPLETE deployment by seconds; a new session per attempt avoids the
    "Request too early" refusal of a next-poll token used before NextPollIntervalInSeconds.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        body = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
        if body == expect or time.monotonic() >= deadline:
            return body
        time.sleep(2.0)


def _wait_terminal(ac, app_id, env_id, dep_num, timeout_s=600, on_tick=None):
    """Poll GetDeployment until the deployment reaches a terminal state, running on_tick each pass."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if on_tick is not None:
            on_tick(last)
        if last.get("State") in _TERMINAL:
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"deployment {dep_num} never reached a terminal state within {timeout_s}s; last "
        f"{(last or {}).get('State')!r} at {(last or {}).get('PercentageComplete')!r}%"
    )


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A deployment whose monitored CloudWatch alarm goes into ALARM during bake is rolled back, and
    appconfigdata serves the previous version's exact bytes again."""
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    cw = ctx.client("cloudwatch")
    iam = ctx.client("iam")

    v1_bytes = b'{"tier":"one"}'
    v2_bytes = b'{"tier":"two"}'

    role_name = ctx.unique_name("sim2real-behav-monrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "appconfig.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["cloudwatch:DescribeAlarms"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))

    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    metric_name = "sim2realRollbackSignal"
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        MetricName=metric_name,
        Namespace=_NAMESPACE,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        Tags=_TAGLIST,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    def _alarm_state():
        return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]

    # The alarm must be demonstrably NOT breaching before the barrier deployment, or that
    # deployment would roll back for the very reason under test.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if _alarm_state() == "OK":
            break
        cw.set_alarm_state(
            AlarmName=alarm_name, StateValue="OK", StateReason="sim2real: baseline healthy"
        )
        time.sleep(2.0)
    assert _alarm_state() == "OK", (
        f"the monitored alarm must start in OK, got {_alarm_state()!r}"
    )

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-"),
        Monitors=[{"AlarmArn": alarm_arn, "AlarmRoleArn": role_arn}],
        Tags=_TAGS,
    )["Id"]
    environment = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert environment["Monitors"] == [{"AlarmArn": alarm_arn, "AlarmRoleArn": role_arn}], (
        f"the environment's Monitors must round-trip both ARNs, got "
        f"{environment.get('Monitors')!r}"
    )
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
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

    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-bake-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=_BAKE_MINUTES,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    strategy = ac.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert strategy["FinalBakeTimeInMinutes"] == _BAKE_MINUTES, (
        f"the strategy must carry a {_BAKE_MINUTES}-minute bake time — with no bake there is no "
        f"window in which a monitor is consulted; got {strategy['FinalBakeTimeInMinutes']!r}"
    )

    # Barrier: a monitored deployment must COMPLETE first. Retried because a not-yet-assumable
    # monitor role also ends in ROLLED_BACK, the state under test.
    baseline = None
    attempts = 0
    deadline = time.monotonic() + _MONITOR_READY_TIMEOUT_S
    while time.monotonic() < deadline:
        attempts += 1
        dep = ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(v1),
            Tags=_TAGS,
        )["DeploymentNumber"]
        settled = _wait_terminal(ac, app_id, env_id, dep, timeout_s=_ROLLBACK_TIMEOUT_S)
        if settled["State"] == "COMPLETE":
            baseline = settled
            break
        time.sleep(10.0)
    assert baseline is not None, (
        f"no monitored deployment reached COMPLETE in {attempts!r} attempts over "
        f"{_MONITOR_READY_TIMEOUT_S}s, so AppConfig could not read the alarm at all; without that "
        f"barrier a later ROLLED_BACK would be unattributable"
    )
    assert any(
        e.get("EventType") == "BAKE_TIME_STARTED" for e in baseline.get("EventLog", [])
    ), (
        f"the barrier deployment must have actually baked — its EventLog must carry "
        f"BAKE_TIME_STARTED; got {[e.get('EventType') for e in baseline.get('EventLog', [])]!r}"
    )
    served_v1 = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert served_v1 == v1_bytes, (
        f"version 1 must be in service before the rollback under test; got {served_v1!r}"
    )

    dep2 = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(v2),
        Tags=_TAGS,
    )["DeploymentNumber"]
    baking_served = None
    deadline = time.monotonic() + _ROLLBACK_TIMEOUT_S
    while time.monotonic() < deadline:
        live = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep2
        )
        if live.get("State") == "BAKING":
            baking_served = _serve_until(acd, app_id, env_id, cp_id, expect=v2_bytes)
            break
        assert live.get("State") not in _TERMINAL, (
            f"the deployment reached {live.get('State')!r} before it ever entered BAKING, so the "
            f"bake-time monitor was never consulted; EventLog "
            f"{[e.get('EventType') for e in live.get('EventLog', [])]!r}"
        )
        time.sleep(2.0)
    assert baking_served == v2_bytes, (
        f"a fully-grown deployment in BAKING must already be serving version 2's exact bytes; got "
        f"{baking_served!r}"
    )

    # Held in ALARM on every poll: CloudWatch re-evaluates a set state and notBreaching returns OK.
    cw.put_metric_data(
        Namespace=_NAMESPACE,
        MetricData=[{"MetricName": metric_name, "Value": 5.0, "Unit": "Count"}],
    )
    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real: forced breach"
    )
    assert _alarm_state() == "ALARM", (
        f"set_alarm_state must move the alarm to ALARM immediately, got {_alarm_state()!r}"
    )

    def _hold_alarm(_deployment):
        if _alarm_state() != "ALARM":
            cw.set_alarm_state(
                AlarmName=alarm_name,
                StateValue="ALARM",
                StateReason="sim2real: forced breach (re-applied)",
            )

    final = _wait_terminal(
        ac, app_id, env_id, dep2, timeout_s=_ROLLBACK_TIMEOUT_S, on_tick=_hold_alarm
    )
    assert final["State"] == "ROLLED_BACK", (
        f"a monitored deployment whose alarm goes into ALARM during bake must terminate "
        f"ROLLED_BACK, got {final['State']!r} — COMPLETE means the monitor was never consulted, "
        f"which is exactly the failure mode a recorded frame cannot catch"
    )
    assert any(
        e.get("EventType") == "ROLLBACK_COMPLETED" for e in final.get("EventLog", [])
    ), (
        f"the EventLog must record ROLLBACK_COMPLETED; got "
        f"{[e.get('EventType') for e in final.get('EventLog', [])]!r}"
    )
    env_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"]
    assert env_state == "RolledBack", (
        f"a rolled-back environment reports the CamelCase State 'RolledBack' while GetDeployment "
        f"reports {final['State']!r} for the same event; got {env_state!r}"
    )

    restored = None
    deadline = time.monotonic() + _ROLLBACK_TIMEOUT_S
    while time.monotonic() < deadline:
        restored = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
        if restored == v1_bytes:
            break
        time.sleep(2.0)
    assert restored == v1_bytes, (
        f"after the alarm-driven rollback the data plane must serve version 1's exact bytes again; "
        f"got {restored!r}"
    )
    assert restored != v2_bytes, (
        "the data plane is still serving the rolled-back version, so the rollback changed only "
        "the deployment record and not what clients receive"
    )
    confirm = _serve_until(acd, app_id, env_id, cp_id, expect=v1_bytes)
    assert confirm == v1_bytes, (
        f"the restoration must be settled, not a transient: a second fresh session was served "
        f"{confirm!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
