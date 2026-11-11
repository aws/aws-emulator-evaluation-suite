"""alarm-monitor-role-not-assumable-deployment-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-monitor-role-not-assumable-deployment-rejected"
GROUP = 'deployment'
SERVICES = ['appconfig', 'cloudwatch']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-monitor-role-denied"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_BAKE_MINUTES = 1
_NAMESPACE = "sim2real/AppConfigMonitorRole"
_MONITOR_READY_TIMEOUT_S = 900
_TERMINAL_TIMEOUT_S = 480
_REFUSAL_TIMEOUT_S = 300

# Account-level AppConfig deletion protection can be enabled, so the deletes below pass
# DeletionProtectionCheck="BYPASS" explicitly.


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


def _make_monitor_role(ctx, iam, trusted_service):
    """A role with cloudwatch:DescribeAlarms whose ONLY variable is which service may assume it."""
    name = ctx.unique_name("sim2real-behav-monrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trusted_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["cloudwatch:DescribeAlarms"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _wait_terminal(ac, app_id, env_id, dep_num, timeout_s=480):
    """Poll GetDeployment until the deployment reaches a terminal state."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"deployment {dep_num} never reached a terminal state within {timeout_s}s; last "
        f"{(last or {}).get('State')!r}"
    )


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll fresh configuration sessions until one serves exactly `expect`; return the last payload.

    The data plane lags COMPLETE by seconds; a new session per attempt avoids "Request too early"
    on a next-poll token presented before NextPollIntervalInSeconds.
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
        time.sleep(3.0)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html
@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CreateEnvironment accepts a monitor role AppConfig cannot assume, then deployments ROLL BACK
    and nothing is served, while a sibling differing only in role trust deploys and serves.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    cw = ctx.client("cloudwatch")
    iam = ctx.client("iam")
    payload = b'{"shared":"between-both-environments"}'

    good_role_arn = _make_monitor_role(ctx, iam, "appconfig.amazonaws.com")
    # The ONE broken thing: the same policy, the same permissions, a different trusted principal.
    broken_role_arn = _make_monitor_role(ctx, iam, "ec2.amazonaws.com")
    assert good_role_arn != broken_role_arn, "the two monitor roles must be distinct"

    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        MetricName="sim2realMonitorRoleSignal",
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
    deadline = time.monotonic() + 180
    state = None
    while time.monotonic() < deadline:
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if state == "OK":
            break
        cw.set_alarm_state(
            AlarmName=alarm_name, StateValue="OK", StateReason="sim2real: baseline healthy"
        )
        time.sleep(3.0)
    assert state == "OK", (
        f"the shared alarm must be healthy so that neither environment rolls back because of the "
        f"alarm itself; got {state!r}"
    )

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    good_env = ac.create_environment(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-good-"),
        Monitors=[{"AlarmArn": alarm_arn, "AlarmRoleArn": good_role_arn}],
        Tags=_TAGS,
    )["Id"]

    # AppConfig does not validate Monitors at create; enforcement is deferred to deployment time.
    broken_env = ac.create_environment(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-broken-"),
        Monitors=[{"AlarmArn": alarm_arn, "AlarmRoleArn": broken_role_arn}],
        Tags=_TAGS,
    )["Id"]
    broken = ac.get_environment(ApplicationId=app_id, EnvironmentId=broken_env)
    assert broken["Monitors"] == [
        {"AlarmArn": alarm_arn, "AlarmRoleArn": broken_role_arn}
    ], (
        f"CreateEnvironment must store an unassumable AlarmRoleArn verbatim rather than validating "
        f"or rewriting it; GetEnvironment returned {broken.get('Monitors')!r}"
    )
    assert broken["State"] == "ReadyForDeployment", (
        f"the environment with the unassumable monitor role must still report "
        f"'ReadyForDeployment', got {broken['State']!r}"
    )

    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType="application/json",
    )["VersionNumber"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-bake-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=_BAKE_MINUTES,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # Retried because a fresh trust policy must propagate; until then AWS rolls back exactly as the
    # broken environment will, so this success rules out timing as the cause below.
    good_final = None
    attempts = 0
    deadline = time.monotonic() + _MONITOR_READY_TIMEOUT_S
    while time.monotonic() < deadline:
        attempts += 1
        dep = ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=good_env,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(version),
            Tags=_TAGS,
        )["DeploymentNumber"]
        settled = _wait_terminal(ac, app_id, good_env, dep, timeout_s=_TERMINAL_TIMEOUT_S)
        if settled["State"] == "COMPLETE":
            good_final = settled
            break
        time.sleep(10.0)
    assert good_final is not None, (
        f"the correctly-trusted monitor role never let a deployment COMPLETE in {attempts!r} "
        f"attempts over {_MONITOR_READY_TIMEOUT_S}s; without that barrier the broken "
        f"environment's rollback would be indistinguishable from IAM propagation"
    )
    good_served = _serve_until(acd, app_id, good_env, cp_id, expect=payload)
    assert good_served == payload, (
        f"the correctly-monitored environment must serve the deployed bytes; got {good_served!r}"
    )

    broken_dep = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=broken_env,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Tags=_TAGS,
    )["DeploymentNumber"]
    broken_final = _wait_terminal(
        ac, app_id, broken_env, broken_dep, timeout_s=_TERMINAL_TIMEOUT_S
    )
    assert broken_final["State"] == "ROLLED_BACK", (
        f"a deployment whose environment monitor role AppConfig cannot assume must terminate "
        f"ROLLED_BACK, got {broken_final['State']!r} — COMPLETE means the emulator ignored "
        f"Monitors entirely and shipped a release with no monitoring at all, which is the "
        f"over-permissive failure this check exists for"
    )
    rollback_events = [
        e for e in broken_final.get("EventLog", []) if e.get("EventType") == "ROLLBACK_COMPLETED"
    ]
    assert rollback_events, (
        f"the EventLog must record ROLLBACK_COMPLETED for the unassumable-role rollback; got "
        f"{[e.get('EventType') for e in broken_final.get('EventLog', [])]!r}"
    )
    rollback_event = rollback_events[-1]
    # The shared alarm stays OK throughout, so the rollback must not be attributed to it.
    assert rollback_event.get("TriggeredBy") != "CLOUDWATCH_ALARM", (
        f"this rollback must not be attributed to the alarm — the shared alarm stayed OK the "
        f"whole run; got TriggeredBy={rollback_event.get('TriggeredBy')!r}"
    )
    assert rollback_event.get("Description") == (
        f"Unable to assume environment monitor role: {broken_role_arn}"
    ), (
        f"the ROLLBACK_COMPLETED Description must name the specific unassumable role ARN, tying "
        f"the rollback to the trust-policy break rather than a generic internal error; got "
        f"{rollback_event.get('Description')!r}"
    )
    assert not any(
        e.get("EventType") == "DEPLOYMENT_COMPLETED"
        for e in broken_final.get("EventLog", [])
    ), (
        f"the rolled-back deployment must never have logged DEPLOYMENT_COMPLETED; got "
        f"{[e.get('EventType') for e in broken_final.get('EventLog', [])]!r}"
    )
    broken_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=broken_env)["State"]
    assert broken_state == "RolledBack", (
        f"the broken environment must settle on the CamelCase State 'RolledBack', got "
        f"{broken_state!r}"
    )

    # Polled because the data plane lags the control plane by seconds.
    session_code = None
    session_message = None
    deadline = time.monotonic() + _REFUSAL_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            acd.start_configuration_session(
                ApplicationIdentifier=app_id,
                EnvironmentIdentifier=broken_env,
                ConfigurationProfileIdentifier=cp_id,
            )
        except ClientError as exc:
            session_code = exc.response["Error"]["Code"]
            session_message = exc.response["Error"].get("Message")
            break
        time.sleep(5.0)
    assert session_code == "ResourceNotFoundException", (
        f"no deployment ever succeeded in the broken environment, so StartConfigurationSession for "
        f"it must be refused with ResourceNotFoundException, got {session_code!r} — anything else "
        f"means the rolled-back configuration is reachable there"
    )
    assert session_message == "Deployment not found", (
        f"unexpected StartConfigurationSession message: {session_message!r}"
    )

    good_after = _serve_until(acd, app_id, good_env, cp_id, expect=payload)
    assert good_after == payload, (
        f"the correctly-monitored sibling must still serve the deployed bytes after its neighbour "
        f"rolled back; got {good_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
