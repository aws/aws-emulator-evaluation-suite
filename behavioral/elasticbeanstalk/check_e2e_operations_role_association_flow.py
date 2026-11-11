"""e2e-operations-role-association-flow."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-operations-role-association-flow"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An operations role round-trips through associate and disassociate on a live environment.

    DescribeEnvironments shows it once associated, a managed action applied meanwhile completes in
    the history, and disassociating clears it before the environment recovers to Ready.
    """
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-behav-opsrole-")
    env_name = ctx.unique_name("sim2real-ops-")
    role_name = ctx.unique_name("sim2real-eb-ops-")[:64]

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "elasticbeanstalk.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ops_role_policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ops_role_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ops_role_policy_arn))
    _wait_for_role_visible(iam, role_name)

    svc_role_name, ec2_profile_name = _create_eb_roles(ctx, iam)

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    # Far enough out that AWS's own weekly window cannot fire mid-run and race the
    # explicit ApplyEnvironmentManagedAction call below with a real one.
    preferred_start = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)
    ).strftime("%a:%H:%M")
    _create_environment_with_retry(
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": preferred_start},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
        ],
    )
    # Registered after the operations role so it runs first (LIFO) and blocks until Terminated:
    # Beanstalk assumes the operations role to terminate, and deleting it first leaves the env
    # unterminatable. TerminateEnvByForce above is fire-and-forget and does not wait.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=1200, require_stable=True)
    _wait_for_health_assessed(eb, env_name, timeout_s=600)

    # Associate: the role becomes visible via DescribeEnvironments -- an independent
    # read through a different operation than the one that mutated.
    _associate_role_with_retry(eb, env_name, role_arn)
    env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
    assert env.get("OperationsRole") == role_arn, (
        f"expected OperationsRole {role_arn!r} after associate, observed {env.get('OperationsRole')!r}"
    )

    # Apply a real scheduled managed action while the operations role is associated,
    # then prove it actually executed via an independent read of the action history --
    # the apply call's own response only proves it was accepted, not that it ran.
    action = _wait_for_scheduled_action(eb, env_name, timeout_s=1200)
    apply_resp = _apply_action_with_retry(eb, env_name, action["ActionId"])
    assert apply_resp["Status"] == "Scheduled", (
        f"expected ApplyEnvironmentManagedAction to report Scheduled, observed {apply_resp['Status']!r}"
    )
    history_item = _wait_for_history_terminal(eb, env_name, action["ActionId"], timeout_s=900)
    assert history_item["Status"] == "Completed", (
        f"expected managed action {action['ActionId']} to reach Completed in history, "
        f"observed {history_item['Status']!r}"
    )

    # Disassociate: the field disappears again.
    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
    env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
    assert env.get("OperationsRole") is None, (
        f"expected OperationsRole to be cleared after disassociate, observed {env.get('OperationsRole')!r}"
    )

    # The environment recovers from the forced instance refresh and stays usable.
    final_env = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=1200)
    assert final_env["EnvironmentName"] == env_name, (
        f"expected the recovered environment to still be named {env_name!r}, "
        f"observed {final_env['EnvironmentName']!r}"
    )


def _create_eb_roles(ctx, iam) -> tuple[str, str]:
    """A custom service role + EC2 instance profile, required because the default
    service-linked role forbids ManagedActionsEnabled."""
    suffix = ctx.unique_name("sim2real-ebmarole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    svc_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    ec2_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })

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


def _terminate_and_wait(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Disassociate any operations role, then terminate and wait for Terminated, re-issuing each
    call while an in-flight update (e.g. a just-made role association) rejects it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if envs[0]["Status"] != "Terminating":
            try:
                if envs[0].get("OperationsRole"):
                    # Beanstalk terminates AS the operations role, which may lack the permissions to.
                    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
                else:
                    eb.terminate_environment(EnvironmentName=env_name)
            except ClientError as err:
                # Refused while an in-flight update holds the environment, or already gone: retried
                # or settled by the next describe; anything else re-raises.
                if err.response["Error"]["Code"] not in ("InvalidParameterValue", "OperationInProgressFailure"):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s:.0f}s")


def _create_environment_with_retry(eb, **kwargs):
    """Bounded retry for IAM eventual consistency: the roles above were just created, and
    Elastic Beanstalk may not yet be able to assume/pass them."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_env_status(
    eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 2.0, require_stable: bool = False
):
    """`require_stable` additionally waits for AbortableOperationInProgress to clear --
    Status can read Ready while a trailing configuration operation still holds the
    environment busy and rejects a new operation with "must be in available state"."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses and (not require_stable or not last.get("AbortableOperationInProgress")):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached a stable {statuses}; last={last}")


def _wait_for_health_assessed(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0):
    """Status can read Ready while Enhanced Health has not yet collected any data
    (Health='Grey', HealthStatus='Pending') -- ApplyEnvironmentManagedAction for an
    InstanceRefresh rejects that as "not in available state" even though Status says Ready."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last.get("Health") != "Grey" and last.get("HealthStatus") not in ("Pending", "NoData", "Unknown"):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} health was never assessed; last={last}")


def _wait_for_scheduled_action(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(
            EnvironmentName=env_name, Status="Scheduled"
        ).get("ManagedActions", [])
        if actions:
            return actions[0]
        time.sleep(interval_s)
    raise AssertionError(f"no Scheduled managed action ever appeared for {env_name}")


def _apply_action_with_retry(eb, env_name: str, action_id: str, timeout_s: float = 600.0, interval_s: float = 2.0):
    """Right after CreateEnvironment settles into Ready, a trailing configuration
    operation can briefly still be in progress and reject a new operation."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if err.response["Error"]["Code"] != "InvalidParameterValue" or "available state" not in msg or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_for_history_terminal(eb, env_name: str, action_id: str, timeout_s: float = 900.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        for item in items:
            if item.get("ActionId") == action_id:
                last = item
                if item.get("Status") in ("Completed", "Failed", "Unknown"):
                    return item
        time.sleep(interval_s)
    raise AssertionError(f"managed action {action_id} never reached a terminal history status; last={last}")


def _wait_for_role_visible(iam, role_name: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    """IAM role creation is eventually consistent; poll GetRole until visible."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(interval_s)
    raise AssertionError(f"role {role_name} never became visible")


def _associate_role_with_retry(eb, env_name: str, role_arn: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    """Freshly created IAM roles can lag briefly behind iam:PassRole checks."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
