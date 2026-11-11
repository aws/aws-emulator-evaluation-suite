"""managed-action-scheduled-then-becomes-pending-after-window."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-action-scheduled-then-becomes-pending-after-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticbeanstalk"]


# timing:real-time — schedule: 175 s https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-platform-update-managed.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A Scheduled managed action transitions to Pending once its maintenance window opens."""
    app_name = _create_app(ctx)
    start_time = _preferred_start_time(minutes_ahead=3)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": start_time},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
    ]
    env_name = _create_ready_environment(ctx, app_name, extra_option_settings=option_settings)

    action = _wait_for_managed_action(ctx, env_name, timeout_s=900.0)
    action_id = action["ActionId"]
    assert action["Status"] == "Scheduled", f"expected freshly-discovered managed action to be Scheduled, got {action['Status']!r}"

    eb = ctx.client("elasticbeanstalk")
    observed_pending = False
    deadline = time.monotonic() + 900.0
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
        match = next((a for a in actions if a["ActionId"] == action_id), None)
        if match is None:
            # Action left the live list (applied/completed) without us observing Pending.
            break
        if match["Status"] == "Pending":
            observed_pending = True
            break
        time.sleep(15.0)
    assert observed_pending, "managed action never transitioned from Scheduled to Pending as the window opened"


_EB_PREFIX = "sim2real-eb-"


def _eb_name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_EB_PREFIX}{kind}-")


def _preferred_start_time(minutes_ahead: int = 3) -> str:
    now = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes_ahead)
    return f"{now.strftime('%a')}:{now.strftime('%H:%M')}"


def _pick_old_platform_arn(ctx: Any) -> str:
    """A platform version with a newer Ready sibling in the same branch, so a minor
    platform update is guaranteed to be available for AWS to recommend -- not merely likely,
    as picking an arbitrary old solution stack would leave it."""
    eb = ctx.client("elasticbeanstalk")
    branches = []
    next_token = None
    while True:
        kwargs: dict[str, Any] = {
            "Filters": [{"Attribute": "LifecycleState", "Operator": "=", "Values": ["supported"]}],
            "MaxRecords": 100,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = eb.list_platform_branches(**kwargs)
        branches.extend(resp.get("PlatformBranchSummaryList", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    for branch in branches:
        name = branch.get("BranchName")
        if not name:
            continue
        versions = eb.list_platform_versions(
            Filters=[{"Type": "PlatformBranchName", "Operator": "=", "Values": [name]}]
        ).get("PlatformSummaryList", [])
        ready = [v for v in versions if v.get("PlatformStatus") == "Ready"]
        if len(ready) >= 2:
            return sorted(v["PlatformArn"] for v in ready)[0]
    raise AssertionError(
        f"none of {len(branches)} supported platform branches currently has two or more Ready "
        "versions, so there is no way to guarantee a minor platform update is available to "
        "schedule right now; AWS's platform catalog periodically retires the superseded version "
        "of a branch once its deprecation window elapses, so this closes once some branch has a "
        "fresh release alongside its still-Ready predecessor"
    )


def _create_app(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    app_name = _eb_name(ctx, "app")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    return app_name


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "ec2role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)

    def _cleanup() -> None:
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_instance_profile(InstanceProfileName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name


def _create_eb_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "svcrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup() -> None:
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_env_with_retry(eb: Any, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            eb.create_environment(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "InsufficientPrivilegesException":
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _wait_for_env_status(
    ctx: Any, env_name: str, target_statuses: set[str], timeout_s: float = 900.0, interval_s: float = 15.0
) -> str:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {target_statuses} within {timeout_s}s (last={last_status})")


def _terminate_environment(ctx: Any, env_name: str) -> None:
    eb = ctx.client("elasticbeanstalk")
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the wanted state; anything else re-raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_for_env_status(ctx, env_name, {"Terminated"}, timeout_s=600.0, interval_s=2.0)


def _create_ready_environment(ctx: Any, app_name: str, extra_option_settings: list | None = None) -> str:
    eb = ctx.client("elasticbeanstalk")
    env_name = _eb_name(ctx, "env")
    platform_arn = _pick_old_platform_arn(ctx)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
    ]
    if extra_option_settings:
        option_settings.extend(extra_option_settings)
    kwargs = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "PlatformArn": platform_arn,
        "OptionSettings": option_settings,
        "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    }
    _create_env_with_retry(eb, kwargs)
    ctx.on_cleanup(lambda: _terminate_environment(ctx, env_name))
    _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0, interval_s=15.0)
    return env_name


def _wait_for_managed_action(ctx: Any, env_name: str, timeout_s: float = 600.0, interval_s: float = 20.0) -> dict:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
            "ManagedActions", []
        )
        if actions:
            return actions[0]
        time.sleep(interval_s)
    raise AssertionError(
        "AWS never scheduled a managed action for this environment within the poll window, even "
        "though the environment was provisioned on a platform version with a newer Ready sibling - "
        "the recommendation engine's internal detection scan had not run yet within this bounded "
        "poll; would be closed by re-running or widening the window"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
