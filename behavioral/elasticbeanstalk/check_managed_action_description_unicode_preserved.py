"""managed-action-description-unicode-preserved."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "managed-action-description-unicode-preserved"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed action's ActionDescription text is preserved byte-identical between
    its appearance in DescribeEnvironmentManagedActions (while Scheduled) and its
    later appearance in DescribeEnvironmentManagedActionHistory (once terminal).
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    stack = _pick_solution_stack(eb)
    instance_profile, service_role = _create_eb_iam_roles(ctx)

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    preferred_start = (datetime.now(timezone.utc) + timedelta(minutes=8)).strftime("%a:%H:%M")
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": preferred_start},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_and_await(eb, env_name))

    _wait_for_env_status(ctx, eb, env_name, {"Ready"}, timeout_s=900)

    action = _poll_for_scheduled_instance_refresh(ctx, eb, env_name, timeout_s=1200)
    if action is None:
        raise AssertionError(
            "AWS did not schedule an InstanceRefresh managed action for the configured "
            "maintenance window within the poll window; managed-action scheduling cadence "
            "is not documented as immediate, so this cannot be forced deterministically"
        )
    action_id = action["ActionId"]
    description_scheduled = action["ActionDescription"]
    assert isinstance(description_scheduled, str) and len(description_scheduled) > 0, (
        f"scheduled managed action {action_id!r} has no usable ActionDescription: "
        f"{description_scheduled!r}"
    )

    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)

    history_item = _poll_for_terminal_history(ctx, eb, env_name, action_id, timeout_s=1200)
    if history_item is None:
        raise AssertionError(
            "the applied managed action never reached a terminal state in the history "
            "within the poll window",
        )

    description_history = history_item["ActionDescription"]
    assert description_history == description_scheduled, (
        "ActionDescription text changed between the scheduled-action listing and "
        "the managed-action history entry for the same ActionId"
    )
    assert history_item["ActionId"] == action_id, (
        f"history lookup returned a different ActionId: {history_item['ActionId']!r} != {action_id!r}"
    )


# ----- helpers -----
def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _create_eb_iam_roles(ctx) -> tuple:
    """The EC2 instance profile and Elastic Beanstalk service role a managed-actions-
    enabled environment needs. Real AWS rejects ManagedActionsEnabled=true outright when
    the environment would fall back to the AWSServiceRoleForElasticBeanstalk service-
    linked role."""
    iam = ctx.client("iam")
    ec2_role = ctx.unique_name("sim2real-eb-desc-ec2-")
    svc_role = ctx.unique_name("sim2real-eb-desc-svc-")
    profile = ctx.unique_name("sim2real-eb-desc-prof-")

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

    _wait_for_iam_propagation(iam, profile, svc_role, timeout_s=60)
    return profile, svc_role


def _wait_for_iam_propagation(iam, instance_profile: str, service_role: str, *, timeout_s: float, interval_s: float = 2.0) -> None:
    """IAM writes are eventually consistent; poll each newly created principal's own read API
    until it is visible, bounded by a deadline, instead of guessing a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=instance_profile)
            iam.get_role(RoleName=service_role)
            return
        except Exception:
            time.sleep(interval_s)


def _poll(ctx, probe, *, timeout_s: float, what: str):
    """probe() every 2 s until it returns a value, or None once timeout_s has passed.

    A wait the runner's budget cuts short is no verdict: it raises a not-graded TimeoutError.
    """
    start = time.monotonic()
    left = ctx.time_left()
    cap_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    while True:
        found = probe()
        if found is not None:
            return found
        if time.monotonic() - start >= cap_s:
            if cap_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, "
                    f"before the {timeout_s:.0f}s wait for {what} ended; not graded"
                )
            return None
        time.sleep(2.0)


def _env(eb, env_name: str) -> dict | None:
    envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
    return envs[0] if envs else None


def _wait_for_env_status(ctx, eb, env_name: str, statuses: set, timeout_s: float) -> dict:
    seen: list = []

    def probe():
        env = _env(eb, env_name)
        seen[:] = [env]
        return env if env and env["Status"] in statuses else None

    found = _poll(ctx, probe, timeout_s=timeout_s, what=f"environment {env_name} to be {statuses}")
    if found is None:
        raise AssertionError(
            f"environment {env_name} did not reach {statuses} within {timeout_s}s (last={seen})"
        )
    return found


def _poll_for_scheduled_instance_refresh(ctx, eb, env_name: str, timeout_s: float):
    def probe():
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
            "ManagedActions", []
        )
        return next((a for a in actions if a.get("ActionType") == "InstanceRefresh"), None)

    return _poll(ctx, probe, timeout_s=timeout_s, what="a scheduled InstanceRefresh action")


def _poll_for_terminal_history(ctx, eb, env_name: str, action_id: str, timeout_s: float):
    def probe():
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        return next(
            (
                item for item in items
                if item.get("ActionId") == action_id
                and item.get("Status") in ("Completed", "Failed", "Unknown")
            ),
            None,
        )

    return _poll(ctx, probe, timeout_s=timeout_s, what=f"managed action {action_id} in the history")


#: How long the teardown waits for Elastic Beanstalk to delete the environment's stack.
TERMINATE_TIMEOUT_S = 600.0


def _terminate_and_await(eb, env_name: str) -> None:
    """Terminate the environment and wait until it is gone, with the instance, Elastic IP and
    security group its stack holds; raises if it is still terminating at the deadline."""
    from botocore.exceptions import ClientError

    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    deadline = time.monotonic() + TERMINATE_TIMEOUT_S
    while True:
        env = _env(eb, env_name)
        if env is None or env["Status"] == "Terminated":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"environment {env_name} still {env['Status']} {TERMINATE_TIMEOUT_S:.0f}s after "
                "TerminateEnvironment"
            )
        time.sleep(2.0)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
