"""managed-action-apply-completed-state-rejected."""
from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-action-apply-completed-state-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Applying a managed action that has already left the 'Scheduled' state (because an
    earlier ApplyEnvironmentManagedAction call already forced it onward) is rejected with
    ManagedActionInvalidStateException, while the first (in-state) apply succeeds."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    _create_managed_updates_environment(ctx, eb, app_name, env_name)

    action = _poll_for_scheduled_action(ctx, eb, env_name, timeout_s=4200.0, interval_s=120.0)
    if action is None:
        raise AssertionError(
            "Elastic Beanstalk never scheduled a managed action for this environment within "
            "the poll window; the API gives no way to force one deterministically, so the "
            "state-conflict path could not be exercised"
        )
    action_id = action["ActionId"]

    # Positive control: forcing a currently-Scheduled action is accepted. The
    # ApplyEnvironmentManagedAction response echoes Status='Scheduled' (the pre-call state)
    # even though the action leaves Scheduled, so the transition is confirmed with an
    # independent describe_environment_managed_action(_history) read instead of the mutating
    # call's own reply.
    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    positive_status = _wait_until_left_scheduled(eb, env_name, action_id, timeout_s=300.0, interval_s=10.0)

    # Negative: re-applying the same action, now that it is no longer Scheduled, is rejected.
    code, message = _error_code(
        lambda: eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    )
    assert code == "ManagedActionInvalidStateException", (
        f"expected ManagedActionInvalidStateException re-applying an action that is "
        f"{positive_status!r} (no longer Scheduled), got {code!r}"
    )
    expected_message = (
        "Managed action is scheduled to execute imminently, is going to be retried, or is already running"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the action did not get reset back to Scheduled by the rejected call.
    remaining = eb.describe_environment_managed_actions(EnvironmentName=env_name)["ManagedActions"]
    scheduled_ids = {a["ActionId"] for a in remaining if a["Status"] == "Scheduled"}
    assert action_id not in scheduled_ids, (
        f"managed action {action_id} is unexpectedly Scheduled again after the rejected reapply; "
        f"scheduled_ids={scheduled_ids!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _current_action_status(eb: Any, env_name: str, action_id: str) -> str | None:
    live = eb.describe_environment_managed_actions(EnvironmentName=env_name)["ManagedActions"]
    match = next((a for a in live if a["ActionId"] == action_id), None)
    if match is not None:
        return match["Status"]
    history = eb.describe_environment_managed_action_history(EnvironmentName=env_name)[
        "ManagedActionHistoryItems"
    ]
    match_h = next((h for h in history if h["ActionId"] == action_id), None)
    return match_h["Status"] if match_h else None


def _wait_until_left_scheduled(eb: Any, env_name: str, action_id: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _current_action_status(eb, env_name, action_id)
        if status is not None and status != "Scheduled":
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"managed action {action_id} did not leave Scheduled within {timeout_s}s "
        f"(last observed status={status!r})"
    )


def _pick_solution_stack(ctx: Any, eb: Any) -> str:
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
    day = target.strftime("%a")  # e.g. "Tue"
    return f"{day}:{target.hour:02d}:{target.minute:02d}"


def _create_eb_service_role(ctx: Any) -> str:
    # Real AWS rejects with ConfigurationValidationException: ManagedActionsEnabled
    # cannot be turned on while the environment uses the default service-linked role
    # 'AWSServiceRoleForElasticBeanstalk' -- it requires a service role carrying the
    # 'AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy' managed policy.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-svcrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "elasticbeanstalk.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
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
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eb_instance_profile(ctx: Any) -> str:
    # Do not depend on the account already having the console-created default
    # 'aws-elasticbeanstalk-ec2-role' -- a freshly provisioned account has none, and
    # CreateEnvironment with no IamInstanceProfile then stalls in Launching indefinitely
    # (it stays in Launching for 15+ minutes) rather than failing fast.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
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
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_name


def _create_environment_with_retry(eb: Any, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    # The service role just created is not always immediately assumable by elasticbeanstalk.
    # amazonaws.com (IAM propagation), which surfaces as InsufficientPrivilegesException.
    last_err: ClientError | None = None
    for _ in range(attempts):
        try:
            eb.create_environment(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException":
                raise
            last_err = err
            time.sleep(delay_s)
    assert last_err is not None, "retry loop exited without ever calling create_environment"
    raise last_err


def _create_managed_updates_environment(ctx: Any, eb: Any, app_name: str, env_name: str) -> None:
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    service_role_arn = _create_eb_service_role(ctx)
    instance_profile_name = _create_eb_instance_profile(ctx)
    stack = _pick_solution_stack(ctx, eb)
    _create_environment_with_retry(eb, {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "SolutionStackName": stack,
        "Tags": [{"Key": "sim2real", "Value": "true"}],
        "OptionSettings": [
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile_name},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": _preferred_start_time_soon()},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
        ],
    })
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))
    _wait_for_env_status(ctx, eb, env_name, {"Ready"}, timeout_s=900.0)


def _poll_for_scheduled_action(ctx: Any, eb: Any, env_name: str, timeout_s: float, interval_s: float) -> dict | None:
    # With InstanceRefreshEnabled, Elastic Beanstalk schedules a weekly instance-refresh
    # managed action independent of platform-update availability, but it still relies on the
    # same periodic scan (documented as roughly hourly) to materialize the Scheduled entry.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled")["ManagedActions"]
        if actions:
            return actions[0]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
