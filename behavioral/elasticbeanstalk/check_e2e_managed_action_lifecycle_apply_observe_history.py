"""e2e-managed-action-lifecycle-apply-observe-history."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-managed-action-lifecycle-apply-observe-history"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Scheduled managed action (InstanceRefresh, scheduled on the configured window regardless of
    platform freshness) that is force-applied leaves the pending list and lands in managed-action
    history with a terminal status."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-ebma-app-")
    env_name = _short_env_name(ctx, "ebma")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    svc_role_name, ec2_profile_name = _create_eb_roles(ctx)

    stack = _pick_solution_stack(ctx)
    preferred_start = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=6)).strftime("%a:%H:%M")
    _create_environment_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": preferred_start},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
        ],
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))
    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"environment entered {env['Status']} instead of Ready"

    pending = _poll_until(
        lambda: eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
            "ManagedActions", []
        ),
        lambda actions: len(actions) > 0,
        timeout_s=1200.0,
        interval_s=30.0,
    )
    if not pending:
        raise AssertionError(
            "AWS never scheduled the InstanceRefresh managed action for this environment within "
            "the poll window, despite ManagedActionsEnabled and an imminent PreferredStartTime; "
            "managed-action scheduling latency is undocumented and cannot be forced further"
        )

    action = pending[0]
    action_id = action["ActionId"]

    applied = eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    assert applied["ActionId"] == action_id

    still_pending = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
        "ManagedActions", []
    )
    assert action_id not in {a["ActionId"] for a in still_pending}, (
        "applied managed action still appears in the Scheduled pending list"
    )

    history_item = _poll_until(
        lambda: next(
            (
                h
                for h in eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
                    "ManagedActionHistoryItems", []
                )
                if h["ActionId"] == action_id
            ),
            None,
        ),
        lambda h: h is not None and h.get("Status") in ("Completed", "Failed", "Unknown"),
        timeout_s=1200.0,
        interval_s=30.0,
    )
    assert history_item is not None, f"managed action {action_id} never appeared in managed-action history"
    assert history_item["Status"] in ("Completed", "Failed", "Unknown"), (
        f"managed action {action_id} history entry has non-terminal status {history_item.get('Status')!r}"
    )


# ===== helpers =====
def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _create_eb_roles(ctx) -> tuple[str, str]:
    """A custom service role + EC2 instance profile, required because the default
    service-linked role forbids ManagedActionsEnabled."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-ebmarole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return svc_name, ec2_name


def _create_environment_with_retry(ctx, eb, **kwargs):
    """Retry on InsufficientPrivilegesException every 2 s for up to 80 s: the roles above were just
    created, and Elastic Beanstalk may not yet be able to assume/pass them."""
    left = ctx.time_left()
    deadline = time.monotonic() + (80.0 if left is None else max(1.0, min(80.0, left - 5.0)))
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _wait_env_status(ctx, env_name: str, targets, timeout_s: float = 1200.0, interval_s: float = 20.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last={last})")


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
