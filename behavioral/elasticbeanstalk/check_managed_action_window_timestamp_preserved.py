"""managed-action-window-timestamp-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-action-window-timestamp-preserved"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A scheduled managed action's WindowStartTime is stable across DescribeEnvironmentManagedActions calls.

    Once the action is applied, its history item carries a real ExecutedTime taken at or after the
    apply, not a copy of WindowStartTime.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-window-")
    env_name = ctx.unique_name("sim2real-win-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    instance_profile, service_role = _create_eb_iam_roles(ctx)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
    ]
    _create_env_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=option_settings,
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900)

    first = _wait_for_scheduled_action(eb, env_name, timeout_s=1500)
    action_id = first["ActionId"]
    window_start_1 = first["WindowStartTime"]

    # A second, independent Describe call for the same still-Scheduled action
    # must report the identical timestamp, not a truncated/re-derived one.
    second = next(
        a
        for a in eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled")[
            "ManagedActions"
        ]
        if a["ActionId"] == action_id
    )
    window_start_2 = second["WindowStartTime"]
    assert window_start_1 == window_start_2, (
        f"WindowStartTime drifted across independent Describe calls for the same "
        f"still-Scheduled action {action_id}: first={window_start_1!r} second={window_start_2!r}"
    )

    apply_time = time.time()
    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    history_item = _wait_for_history_terminal(eb, env_name, action_id, timeout_s=1200)
    read_time = time.time()

    executed_time = history_item["ExecutedTime"]
    # ExecutedTime must be a real timestamp taken at/after the Apply call, not
    # zeroed or copied verbatim from WindowStartTime (which was scheduled for
    # a future weekly window, not "now"), and not later than the wall-clock
    # instant we observed it in history.
    assert apply_time - 60 <= executed_time.timestamp() <= read_time + 1, (
        f"ExecutedTime {executed_time!r} is not within the applied window "
        f"[{apply_time - 60}, {read_time + 1}] (apply_time={apply_time}, read_time={read_time})"
    )
    assert executed_time != window_start_1, (
        f"ExecutedTime {executed_time!r} was copied verbatim from the scheduled "
        f"WindowStartTime {window_start_1!r} instead of reflecting the actual Apply run"
    )


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _create_eb_iam_roles(ctx) -> tuple:
    """The EC2 instance profile and Elastic Beanstalk service role a managed-actions-
    enabled environment needs. Real AWS rejects ManagedActionsEnabled=true outright when
    the environment would fall back to the AWSServiceRoleForElasticBeanstalk service-
    linked role, so this is not optional plumbing -- it is the prerequisite the check
    exists to exercise past."""
    iam = ctx.client("iam")
    ec2_role = ctx.unique_name("sim2real-eb-window-ec2-")
    svc_role = ctx.unique_name("sim2real-eb-window-svc-")
    profile = ctx.unique_name("sim2real-eb-window-prof-")

    ec2_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))
    iam.create_instance_profile(InstanceProfileName=profile)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=ec2_role))

    svc_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=svc_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_role, PolicyArn=p))

    return profile, svc_role


def _create_env_with_retry(ctx, eb, **kwargs) -> dict:
    """CreateEnvironment, retried over the refusal Elastic Beanstalk returns while the IAM
    principals just created are not yet visible to it; anything else re-raises."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else max(1.0, min(120.0, left - 5.0)))
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if time.monotonic() >= deadline or not (
                exc.response["Error"]["Code"] in ("InvalidParameterValue", "InsufficientPrivilegesException")
                and ("role" in msg or "instance profile" in msg or "permission" in msg)
            ):
                raise
            time.sleep(2)


def _wait_for_env_status(eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses}; last={last}")


def _wait_for_scheduled_action(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(
            EnvironmentName=env_name, Status="Scheduled"
        ).get("ManagedActions", [])
        if actions:
            return actions[0]
        time.sleep(interval_s)
    raise AssertionError(f"no Scheduled managed action ever appeared for {env_name}")


def _wait_for_history_terminal(eb, env_name: str, action_id: str, timeout_s: float = 1200.0, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        for item in items:
            if item["ActionId"] == action_id and item["Status"] in ("Completed", "Failed", "Unknown"):
                return item
        time.sleep(interval_s)
    raise AssertionError(f"managed action {action_id} never reached a terminal history state")


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
