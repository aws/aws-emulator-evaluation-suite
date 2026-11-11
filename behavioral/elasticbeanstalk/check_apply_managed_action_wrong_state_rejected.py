"""apply-managed-action-wrong-state-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apply-managed-action-wrong-state-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a Ready environment with managed actions and instance refresh enabled, applying the Scheduled action
    moves it out of Scheduled, and re-applying it is rejected with ManagedActionInvalidStateException and its
    exact message."""
    eb = ctx.client("elasticbeanstalk")
    app_name = _create_app(ctx)
    env_name = _create_environment(
        ctx,
        app_name,
        extra_option_settings=[
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            # Instance refresh makes Elastic Beanstalk schedule an InstanceRefresh action for the
            # next weekly window, so a Scheduled action exists whether or not a platform update is.
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
        ],
    )
    # One shared deadline, not two independent windows: the runner kills the whole check body at
    # its own ceiling, and two fixed windows that individually look safe can still sum past it.
    # Whatever Ready-wait leaves over is what the Scheduled-action poll gets.
    _TOTAL_BUDGET_S = 1650.0
    deadline = time.monotonic() + _TOTAL_BUDGET_S
    _wait_env_status(ctx, env_name, {"Ready"}, timeout_s=deadline - time.monotonic(), interval_s=15)

    # AWS schedules managed actions on its own cadence after the environment settles; poll for
    # one to appear rather than assuming a fixed delay.
    action = _poll_for_scheduled_action(ctx, env_name, timeout_s=max(60.0, deadline - time.monotonic()), interval_s=20)
    if action is None:
        raise AssertionError(
            f"no managed action reached Scheduled status for {env_name} within the poll "
            "window; Elastic Beanstalk schedules managed actions on its own internal cadence "
            "which this bounded check cannot force to occur sooner"
        )
    action_id = action["ActionId"]

    # Positive control: applying a Scheduled action succeeds and moves it out of Scheduled.
    # The apply response can still echo "Scheduled" the instant it returns, so an independent
    # describe, polled until the action leaves Scheduled, is the verdict.
    _apply_when_environment_ready(ctx, eb, env_name, action_id, timeout_s=600.0)
    post_apply_status = _wait_for_action_status_change(ctx, env_name, action_id, "Scheduled", timeout_s=300.0, interval_s=10.0)
    assert post_apply_status != "Scheduled", f"expected non-Scheduled status after apply, got {post_apply_status!r}"

    # Negative: re-applying the SAME action now that it is no longer Scheduled is rejected.
    code, message = _error_code(
        lambda: eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    )
    assert code == "ManagedActionInvalidStateException", f"unexpected code: {code!r} ({message!r})"
    expected = "Managed action is scheduled to execute imminently, is going to be retried, or is already running"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _apply_when_environment_ready(ctx, eb, env_name, action_id, timeout_s=600.0):
    """Apply the Scheduled action. Elastic Beanstalk can run a short update of its own right
    after the environment first reports Ready, and refuses the apply with InvalidParameterValue
    "Environment must be in available state." until it settles; that refusal is waited out
    (bounded), any other error is raised."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
        except ClientError as err:
            e = err.response["Error"]
            busy = (e["Code"], e.get("Message")) == ("InvalidParameterValue", "Environment must be in available state.")
            if not busy or time.monotonic() >= deadline:
                raise
        _wait_env_status(ctx, env_name, {"Ready"}, timeout_s=max(30.0, deadline - time.monotonic()), interval_s=15)
        time.sleep(2)


def _error_code(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so an
    emulator accepting a call real AWS refuses is never read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_app(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    name = ctx.unique_name("sim2real-eb-mgda-app-")
    eb.create_application(ApplicationName=name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=name, TerminateEnvByForce=True))
    return name


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    # AWS lists solution stacks newest-first per platform branch. Picking the OLDEST surviving
    # Amazon Linux 2 / Python stack (not the newest) maximizes the odds a minor/patch update is
    # actually pending -- the newest stack in the list has nothing to update to.
    candidates = [s for s in stacks if "Amazon Linux 2" in s and "Python" in s and "Running" in s]
    return candidates[-1] if candidates else stacks[-1]


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-mgda-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": "true"}])
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=[{"Key": "sim2real", "Value": "true"}])
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
    role_name = ctx.unique_name("sim2real-eb-mgda-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": "true"}])["Role"]
    # Managed platform updates refuse the default service-linked role outright
    # (ConfigurationValidationException) and require this exact managed policy.
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


def _create_environment(ctx, app_name: str, extra_option_settings: list[dict[str, Any]] | None = None) -> str:
    from botocore.exceptions import ClientError

    eb = ctx.client("elasticbeanstalk")
    env_name = ctx.unique_name("sim2real-eb-mgda-env-")
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"},
    ]
    if extra_option_settings:
        option_settings.extend(extra_option_settings)
    kwargs = dict(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=_pick_solution_stack(ctx),
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=option_settings,
    )
    # A role just created by IAM is not always immediately assumable by another service.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eb.create_environment(**kwargs)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name, ForceTerminate=True))
    return env_name


def _wait_env_status(ctx, env_name: str, target_statuses: set[str], timeout_s: float, interval_s: float) -> dict:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if envs:
            last = envs[0]["Status"]
            if last in target_statuses:
                return envs[0]
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {target_statuses} (last status={last!r})")


def _wait_for_action_status_change(ctx: Any, env_name: str, action_id: str, from_status: str, timeout_s: float, interval_s: float) -> str:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        live = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
        match = next((a for a in live if a["ActionId"] == action_id), None)
        if match is None:
            history = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get("ManagedActionHistoryItems", [])
            match = next((i for i in history if i["ActionId"] == action_id), None)
        last = match["Status"] if match else None
        if last is not None and last != from_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"managed action {action_id} never left status {from_status!r} within {timeout_s}s; last={last!r}")


def _poll_for_scheduled_action(ctx: Any, env_name: str, timeout_s: float = 900, interval_s: float = 20) -> dict | None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
        for action in actions:
            if action.get("Status") == "Scheduled":
                return action
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
