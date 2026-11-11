"""apply-managed-action-invalid-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apply-managed-action-invalid-state-rejected"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Applying a Scheduled managed action moves it out of Scheduled, and applying the same action again is
    rejected with ManagedActionInvalidStateException and its exact message without rescheduling it."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-badstate-")
    env_name = ctx.unique_name("sim2real-bad-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    # Managed platform updates reject the default service-linked role (real AWS:
    # ConfigurationValidationException, "You can't enable managed platform updates when your
    # environment uses the service-linked role ... Select a service role that has the
    # AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy managed policy"), so a custom service
    # role and instance profile must be created and attached.
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)

    stack = _pick_solution_stack(eb)
    _create_environment_with_retry(
        eb,
        dict(
            ApplicationName=app_name,
            EnvironmentName=env_name,
            SolutionStackName=stack,
            Tags=[{"Key": "sim2real", "Value": "true"}],
            OptionSettings=[
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
                {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
                {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
                {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
            ],
        ),
    )
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900)

    action = _wait_for_scheduled_action(eb, env_name, timeout_s=600)
    action_id = action["ActionId"]

    # Positive control: applying a Scheduled action succeeds. ApplyEnvironmentManagedAction's own
    # response is not the verdict (real AWS: it can still echo "Scheduled" the instant the call
    # returns, before the transition lands) -- an independent describe, polled, is.
    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    post_apply_status = _wait_for_action_status_change(eb, env_name, action_id, "Scheduled", timeout_s=300)
    assert post_apply_status != "Scheduled", (
        f"expected the first apply of {action_id} (positive control) to move it out of "
        f"Scheduled, still {post_apply_status!r}"
    )

    # Negative: applying the same action again while it is Running is rejected.
    def _apply_again():
        return eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)

    code, message = _error_code(_apply_again)
    assert code == "ManagedActionInvalidStateException", (
        f"expected re-applying {action_id} while Running to fail with "
        f"ManagedActionInvalidStateException, got {code!r} ({message!r})"
    )
    expected = "Managed action is scheduled to execute imminently, is going to be retried, or is already running"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the action did not get re-scheduled/duplicated -- it no
    # longer shows up as Scheduled (it is already past that state).
    still_scheduled = eb.describe_environment_managed_actions(
        EnvironmentName=env_name, Status="Scheduled"
    )["ManagedActions"]
    scheduled_ids = {a["ActionId"] for a in still_scheduled}
    assert action_id not in scheduled_ids, (
        f"expected {action_id} to be absent from Scheduled actions after the rejected "
        f"re-apply, but it is still listed as Scheduled: {scheduled_ids!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the re-apply to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_eb_instance_profile(ctx) -> str:
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

    def _cleanup():
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


def _create_eb_service_role(ctx) -> str:
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

    def _cleanup():
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


def _create_environment_with_retry(eb, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    """A just-created IAM role/instance-profile is not always immediately visible to Elastic
    Beanstalk (IAM's own eventual consistency), so CreateEnvironment can transiently answer
    InsufficientPrivilegesException. Retry that specific code; anything else raises."""
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
    raise last_err


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


def _current_action_status(eb, env_name: str, action_id: str):
    live = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
    match = next((a for a in live if a["ActionId"] == action_id), None)
    if match is not None:
        return match["Status"]
    history = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
        "ManagedActionHistoryItems", []
    )
    match_h = next((i for i in history if i["ActionId"] == action_id), None)
    return match_h["Status"] if match_h else None


def _wait_for_action_status_change(eb, env_name: str, action_id: str, from_status: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _current_action_status(eb, env_name, action_id)
        if last is not None and last != from_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"managed action {action_id} never left status {from_status!r} within {timeout_s}s; last={last!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
