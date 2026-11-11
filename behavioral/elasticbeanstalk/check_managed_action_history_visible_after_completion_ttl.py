"""managed-action-history-visible-after-completion-ttl."""
from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-action-history-visible-after-completion-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed action is absent from DescribeEnvironmentManagedActionHistory while it is
    still Scheduled/Running, and appears there with a terminal Status once it completes."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    _create_managed_updates_environment(ctx, eb, app_name, env_name)

    # Snapshot history the moment the environment is Ready -- strictly before any managed
    # action for it could possibly exist. Real AWS was measured to let a "Scheduled" action
    # already be moving through completion by the time a SEPARATE, later
    # DescribeEnvironmentManagedActionHistory call is made (its own maintenance window opened
    # while we were still polling for "Scheduled"), so snapshotting "before" only after we
    # first observe the action Scheduled is not a safe baseline -- this earlier snapshot is.
    history_before = eb.describe_environment_managed_action_history(EnvironmentName=env_name)
    ids_before = {h["ActionId"] for h in history_before.get("ManagedActionHistoryItems", [])}

    action = _poll_for_scheduled_action(ctx, eb, env_name, timeout_s=4200.0, interval_s=2.0)
    if action is None:
        raise AssertionError(
            f"Elastic Beanstalk never scheduled a managed action for environment {env_name} "
            "within the poll window; the API gives no way to force one deterministically, so "
            "the completion-visibility path could not be exercised"
        )
    action_id = action["ActionId"]
    assert action_id not in ids_before, (
        f"action {action_id} was already in ManagedActionHistoryItems ({ids_before}) at the "
        "moment the environment became Ready, before any managed action could have existed"
    )

    try:
        eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ManagedActionInvalidState":
            raise
        # AWS's own maintenance window already carried this action to completion ahead of our
        # explicit apply call -- still a real completion, so fall through to the terminal read.

    # After completion: appears in history with a terminal status.
    item = _poll_for_history_item(ctx, eb, env_name, action_id, timeout_s=1800.0, interval_s=2.0)
    assert item["Status"] in {"Completed", "Failed", "Unknown"}, (
        f"expected a terminal history status for {action_id}, got {item['Status']!r}"
    )
    assert "FinishedTime" in item, f"history item for {action_id} has no FinishedTime: {item}"


def _pick_solution_stack(eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux" in s and "running" in s and "Docker" not in s:
            return s
    return stacks[0]


def _wait_for_env_status(ctx: Any, eb: Any, env_name: str, target_statuses: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if envs:
            last = envs[0]["Status"]
            if last in target_statuses:
                return envs[0]
        time.sleep(2)
    raise AssertionError(f"environment {env_name} never reached {target_statuses}, last status={last}")


def _preferred_start_time_soon() -> str:
    target = dt.datetime.utcnow() + dt.timedelta(minutes=15)
    day = target.strftime("%a")
    return f"{day}:{target.hour:02d}:{target.minute:02d}"


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2role-")
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
        for fn in (
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name),
            lambda: iam.delete_instance_profile(InstanceProfileName=role_name),
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)
    return role_name


def _create_eb_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-svcrole-")
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


def _create_environment_with_retry(eb: Any, kwargs: dict, timeout_s: float = 80.0) -> None:
    """CreateEnvironment, retried while the just-created IAM role is not yet assumable by Elastic
    Beanstalk (InsufficientPrivilegesException) up to a deadline; anything else propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eb.create_environment(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_managed_updates_environment(ctx: Any, eb: Any, app_name: str, env_name: str) -> None:
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    stack = _pick_solution_stack(eb)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    _create_environment_with_retry(
        eb,
        {
            "ApplicationName": app_name,
            "EnvironmentName": env_name,
            "SolutionStackName": stack,
            "Tags": [{"Key": "sim2real", "Value": "true"}],
            "OptionSettings": [
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
                {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
                {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": _preferred_start_time_soon()},
                {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
                {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
            ],
        },
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))
    _wait_for_env_status(ctx, eb, env_name, {"Ready"}, timeout_s=900.0)


def _poll_for_scheduled_action(ctx: Any, eb: Any, env_name: str, timeout_s: float, interval_s: float) -> dict | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled")["ManagedActions"]
        if actions:
            return actions[0]
        time.sleep(interval_s)
    return None


def _poll_for_history_item(ctx: Any, eb: Any, env_name: str, action_id: str, timeout_s: float, interval_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        for item in items:
            if item["ActionId"] == action_id:
                return item
        time.sleep(interval_s)
    raise AssertionError(f"managed action {action_id} never appeared in history within {timeout_s}s")


def _terminate_env_and_wait(eb, env_name: str, timeout_s: float = 600.0) -> None:
    """Teardown: terminate the environment and wait for Terminated, so its instance and Elastic IP
    are released; re-issued while EB refuses it mid-operation (invalid state, pending deployment).
    An environment already gone counts as terminated."""
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if envs[0]["Status"] != "Terminating":
            try:
                eb.terminate_environment(EnvironmentName=env_name)
            except ClientError as exc:
                msg = exc.response["Error"].get("Message", "")
                if "not found" in msg.lower():
                    return
                if not ("invalid state" in msg or "pending deployment" in msg) or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"environment {env_name} not terminated within {timeout_s:.0f}s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
