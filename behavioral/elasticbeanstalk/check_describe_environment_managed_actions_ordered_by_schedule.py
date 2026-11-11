"""describe-environment-managed-actions-ordered-by-schedule."""
from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-environment-managed-actions-ordered-by-schedule"
GROUP = "ordering"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEnvironmentManagedActions returns pending/in-progress actions ordered by
    ascending scheduled execution time (WindowStartTime)."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    _create_managed_updates_environment(ctx, eb, app_name, env_name)

    actions = _poll_for_actions(ctx, eb, env_name, timeout_s=900.0, interval_s=20.0)
    if actions is None:
        raise AssertionError(
            "Elastic Beanstalk never scheduled any managed action for this environment within "
            "the poll window, even though it was deliberately launched on an outdated platform "
            "version with a newer Ready version available on the same branch; the recommendation "
            "scan runs on an internal, undocumented cadence this bounded check cannot force"
        )

    # A real environment rarely has more than one concurrently pending managed action (there
    # is no API to force a second one at a different WindowStartTime on demand), but the
    # ordering invariant must hold for whatever the service actually returns.
    window_starts = [a["WindowStartTime"] for a in actions]
    assert window_starts == sorted(window_starts), (
        f"expected ManagedActions ordered by ascending WindowStartTime, got {window_starts}"
    )
    for action in actions:
        # ActionStatus also models "Unknown", but DescribeEnvironmentManagedActions is documented
        # to list only "upcoming and in-progress" actions -- Scheduled (upcoming) or Pending/Running
        # (in-progress). Accepting "Unknown" here would match the operation's full modelled enum
        # and could never fail against any real response.
        assert action["Status"] in {"Scheduled", "Pending", "Running"}, (
            f"DescribeEnvironmentManagedActions lists upcoming/in-progress actions only; got "
            f"Status={action['Status']!r} for action {action.get('ActionId')!r}"
        )


def _pick_old_solution_stack(eb: Any) -> str:
    """The OLDEST Amazon Linux 2, non-Docker stack in a runtime family that ships more than one
    Ready version.

    Managed platform updates are only ever scheduled when a newer minor version exists for the
    environment's current platform branch. Picking the *newest* available stack guarantees there
    is nothing newer to update to, so no managed action could ever be
    scheduled no matter how long the poll waits.
    """
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for runtime in ("Python", "Node.js", "Java", "PHP", "Ruby"):
        family = [s for s in stacks if runtime in s and "Amazon Linux 2" in s and "Docker" not in s]
        if len(family) >= 2:
            return family[-1]
    fallback = [s for s in stacks if "Amazon Linux" in s and "running" in s and "Docker" not in s]
    return fallback[-1] if fallback else stacks[-1]


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


def _create_instance_profile(ctx: Any, iam: Any) -> str:
    name = ctx.unique_name("sim2real-eb-ec2role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name))
    return name


def _create_service_role(ctx: Any, iam: Any) -> str:
    name = ctx.unique_name("sim2real-eb-svcrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": "true"}]
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
    return role_arn


def _create_environment_with_retry(eb: Any, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
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


def _create_managed_updates_environment(ctx: Any, eb: Any, app_name: str, env_name: str) -> None:
    iam = ctx.client("iam")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    instance_profile = _create_instance_profile(ctx, iam)
    service_role_arn = _create_service_role(ctx, iam)
    # IAM eventual consistency before Elastic Beanstalk can assume/pass these roles is bounded by
    # _create_environment_with_retry's own retry-on-InsufficientPrivilegesException below, not a sleep.

    stack = _pick_old_solution_stack(eb)
    _create_environment_with_retry(
        eb,
        {
            "ApplicationName": app_name,
            "EnvironmentName": env_name,
            "SolutionStackName": stack,
            "Tags": [{"Key": "sim2real", "Value": "true"}],
            "OptionSettings": [
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
                {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
                {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": _preferred_start_time_soon()},
                {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
                {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
            ],
        },
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))
    _wait_for_env_status(ctx, eb, env_name, {"Ready"}, timeout_s=900.0)


def _poll_for_actions(ctx: Any, eb: Any, env_name: str, timeout_s: float, interval_s: float) -> list | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name)["ManagedActions"]
        if actions:
            return actions
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
