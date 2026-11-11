"""managed-action-apply-then-appears-in-history."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-action-apply-then-appears-in-history"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ApplyEnvironmentManagedAction forces a Scheduled managed action to run, and it then appears as Completed in the history.

    InstanceRefreshEnabled schedules the action without depending on a newer platform version,
    so a real managed action exists on demand.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=_env_option_settings(ctx),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: eb.terminate_environment(EnvironmentName=env_name, TerminateResources=True)))

    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900.0)

    preferred_start = (datetime.now(timezone.utc) + timedelta(minutes=8)).strftime("%a:%H:%M")
    eb.update_environment(
        EnvironmentName=env_name,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": preferred_start},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
        ],
    )
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=300.0)

    action = _poll_for_scheduled_instance_refresh(eb, env_name, timeout_s=1200.0)
    if action is None:
        raise AssertionError(
            "AWS did not schedule an InstanceRefresh managed action for the configured "
            "maintenance window within the test window; managed-action scheduling cadence "
            "is not documented as immediate, so this cannot be forced deterministically"
        )
    action_id = action["ActionId"]
    # NOT `action["ActionType"] == "InstanceRefresh"` -- that is guaranteed by
    # _poll_for_scheduled_instance_refresh's own filter and can never fail. What the
    # `Status="Scheduled"` server-side filter itself is supposed to guarantee is that every
    # returned item really is Scheduled -- assert that instead.
    assert action["Status"] == "Scheduled", (
        f"describe_environment_managed_actions(Status='Scheduled') returned an action whose own "
        f"Status is {action.get('Status')!r}, not 'Scheduled'"
    )

    applied = eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    assert applied["ActionId"] == action_id, (
        f"ApplyEnvironmentManagedAction echoed ActionId {applied.get('ActionId')!r}, expected {action_id!r}"
    )

    history_item = _poll_history_terminal(eb, env_name, action_id, timeout_s=900.0)
    assert history_item is not None, f"ActionId {action_id} never reached a terminal history status"
    assert history_item["Status"] == "Completed", (
        f"expected the applied action to reach Completed, got {history_item['Status']!r}"
    )
    assert history_item["ActionType"] == "InstanceRefresh", (
        f"expected the history item's ActionType to remain InstanceRefresh, got {history_item['ActionType']!r}"
    )


def _safe(fn) -> None:
    """Run one teardown call; only an already-gone resource is tolerated, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        # IAM reports NoSuchEntity; Elastic Beanstalk reports a missing environment or
        # application as InvalidParameterValue "... not found".
        err = exc.response["Error"]
        if not (err["Code"] == "NoSuchEntity" or (err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", ""))):
            raise


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment needs,
    registering LIFO teardown. Returns (instance_profile|None, service_role|None); degrades
    to (None, None) when IAM is unreachable, letting the service apply its own defaults. A
    fresh account has no "aws-elasticbeanstalk-ec2-role" / "aws-elasticbeanstalk-
    service-role" (those are normally auto-created by the EB console on first use), and
    create_environment with no ServiceRole/IamInstanceProfile then launches straight to
    Terminated instead of Ready."""
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        return None, None

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        except Exception as exc:
            if "EntityAlreadyExists" not in str(exc):
                return False
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=name)))
        for arn in policy_arns:
            try:
                iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                ctx.on_cleanup(lambda a=arn: _safe(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=a)))
            except Exception:
                pass
        return True

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-service-role-")
    profile = ctx.unique_name("sim2real-eb-ec2-profile-")
    ec2_ok = _create_role(
        ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"]
    )
    service_role = (
        svc_role
        if _create_role(
            svc_role,
            "elasticbeanstalk.amazonaws.com",
            [
                "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
                "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
            ],
        )
        else None
    )
    instance_profile = None
    if ec2_ok:
        made = True
        try:
            iam.create_instance_profile(InstanceProfileName=profile)
            ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile)))
        except Exception as exc:
            if "EntityAlreadyExists" not in str(exc):
                made = False
        if made:
            try:
                iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                ctx.on_cleanup(
                    lambda: _safe(
                        lambda: iam.remove_role_from_instance_profile(
                            InstanceProfileName=profile, RoleName=ec2_role
                        )
                    )
                )
            except Exception:
                pass
            instance_profile = profile
    _wait_for_iam_propagation(iam, instance_profile, service_role, timeout_s=30.0)
    return instance_profile, service_role


def _wait_for_iam_propagation(iam, instance_profile, service_role, *, timeout_s: float, interval_s: float = 2.0) -> None:
    """IAM writes are eventually consistent; poll each newly created principal's own read API
    until it is visible, bounded by a deadline, instead of guessing a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ready = True
        if instance_profile:
            try:
                iam.get_instance_profile(InstanceProfileName=instance_profile)
            except Exception:
                ready = False
        if ready and service_role:
            try:
                iam.get_role(RoleName=service_role)
            except Exception:
                ready = False
        if ready:
            return
        time.sleep(interval_s)


def _env_option_settings(ctx) -> list:
    """Baseline option settings that make a single-instance environment actually launch."""
    instance_profile, service_role = _ensure_env_iam(ctx)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    if instance_profile:
        settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"}
        )
    return settings


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _wait_for_env_status(eb, env_name: str, statuses: set, timeout_s: float, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"environment {env_name} did not reach {statuses} within {timeout_s}s "
        f"(last status={last['Status'] if last else None})"
    )


def _poll_for_scheduled_instance_refresh(eb, env_name: str, timeout_s: float, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled")
        actions = resp.get("ManagedActions", [])
        for a in actions:
            if a.get("ActionType") == "InstanceRefresh":
                return a
        time.sleep(interval_s)
    return None


def _poll_history_terminal(eb, env_name: str, action_id: str, timeout_s: float, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        for item in items:
            if item.get("ActionId") == action_id and item.get("Status") in ("Completed", "Failed", "Unknown"):
                return item
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
