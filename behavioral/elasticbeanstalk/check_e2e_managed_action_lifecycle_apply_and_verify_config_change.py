"""e2e-managed-action-lifecycle-apply-and-verify-config-change."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-managed-action-lifecycle-apply-and-verify-config-change"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ApplyEnvironmentManagedAction runs the scheduled InstanceRefresh action now; it reaches Completed
    in the action history and the same environment returns to Ready with DateUpdated not regressed."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-mgda-")
    env_name = ctx.unique_name("sim2real-mgda-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    service_role_arn = _create_eb_service_role(ctx)
    instance_profile_name = _create_eb_instance_profile(ctx)

    stack = _pick_solution_stack(eb)
    _create_environment_with_retry(
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile_name},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
        ],
    )

    env_before = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900)
    date_updated_before = env_before["DateUpdated"]

    action = _wait_for_scheduled_action(eb, env_name, timeout_s=600)
    assert action["ActionType"] == "InstanceRefresh", (
        f"expected the scheduled managed action to be InstanceRefresh, got {action['ActionType']!r}"
    )
    action_id = action["ActionId"]

    apply_resp = eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    # The apply response's Status is a snapshot and can still read "Scheduled" before it advances
    # to Running, so it is checked against pre-terminal states; the history read proves the transition.
    assert apply_resp["Status"] in ("Running", "Scheduled", "Pending"), (
        f"expected ApplyEnvironmentManagedAction to report a pre-terminal Status, got {apply_resp['Status']!r}"
    )

    history_item = _wait_for_history_terminal(eb, env_name, action_id, timeout_s=1200)
    assert history_item["Status"] == "Completed", (
        f"expected the applied managed action to reach terminal Status=Completed, got {history_item['Status']!r}"
    )

    env_after = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900)
    assert env_after["EnvironmentId"] == env_before["EnvironmentId"], (
        f"expected the same EnvironmentId across the managed action, "
        f"before={env_before['EnvironmentId']!r} after={env_after['EnvironmentId']!r}"
    )
    assert env_after["DateUpdated"] >= date_updated_before, (
        f"expected DateUpdated to advance (or stay equal) after the managed action, "
        f"before={date_updated_before!r} after={env_after['DateUpdated']!r}"
    )



def _create_eb_service_role(ctx) -> str:
    """Managed actions reject the default AWSServiceRoleForElasticBeanstalk with
    ConfigurationValidationException, so create a service role carrying
    AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mgda-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
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
    return role["Arn"]


def _create_eb_instance_profile(ctx) -> str:
    """Without an instance profile the EC2 host cannot report health back to Elastic Beanstalk
    and the environment stays in Launching indefinitely."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mgda-ec2role-")
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


def _create_environment_with_retry(eb, *, attempts: int = 8, delay_s: float = 10.0, **kwargs) -> None:
    """Retry InsufficientPrivilegesException: a just-created IAM role is not immediately
    assumable by elasticbeanstalk.amazonaws.com (IAM eventual consistency)."""
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


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
