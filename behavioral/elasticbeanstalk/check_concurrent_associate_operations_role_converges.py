"""concurrent-associate-operations-role-converges."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-operations-role-converges"
GROUP = "concurrency"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AssociateEnvironmentOperationsRole calls with two different roles on the same
    environment converge to a single consistent role association (exactly one of the two ARNs),
    never a corrupted/empty value, and the environment otherwise remains healthy."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-ebrole-app-")
    env_name = _short_env_name(ctx, "ebrole")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_a_name = ctx.unique_name("sim2real-eb-rolea-")[-63:]
    role_b_name = ctx.unique_name("sim2real-eb-roleb-")[-63:]
    role_tags = [{"Key": "sim2real", "Value": CHECK}]
    role_a_arn = iam.create_role(
        RoleName=role_a_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=role_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_a_name))
    role_b_arn = iam.create_role(
        RoleName=role_b_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=role_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_b_name))

    svc_role_name, ec2_profile_name = _create_eb_launch_roles(ctx)

    stack = _pick_solution_stack(ctx)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
        ],
    )
    # Blocks until Terminated, and runs before the operations roles' teardown (LIFO): Beanstalk
    # assumes the role to terminate, and deleting it first leaves the env unterminatable.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"environment entered {env['Status']} instead of Ready"

    def _associate(role_arn: str):
        _retry_insufficient_privileges(
            lambda: eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn),
            timeout_s=60.0,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(_associate, [role_a_arn, role_b_arn]))

    described = _poll_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0],
        lambda e: "OperationsRole" in e,
        timeout_s=60.0,
        interval_s=5.0,
    )
    final_role = described.get("OperationsRole")
    assert final_role in (role_a_arn, role_b_arn), (
        f"final OperationsRole={final_role!r} is neither racer's role ARN -- state corrupted by the race"
    )
    assert described["Status"] in ("Ready", "Updating"), (
        f"environment status {described['Status']!r} indicates the race left the environment unhealthy"
    )


# ===== helpers =====
def _create_eb_launch_roles(ctx) -> tuple[str, str]:
    """Create the EB service role + EC2 instance profile explicitly -- a freshly provisioned
    account has no console-bootstrapped 'aws-elasticbeanstalk-*' defaults, so create_environment
    without these hangs at Status=Launching indefinitely instead of failing loudly."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-ebrole-")
    svc_name = f"{suffix}-svc"[-63:]
    ec2_name = f"{suffix}-ec2"[-63:]

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
    role_tags = [{"Key": "sim2real", "Value": CHECK}]

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))

    iam.create_instance_profile(InstanceProfileName=ec2_name, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    _wait_for_role_visible(iam, svc_name)
    _wait_for_role_visible(iam, ec2_name)
    _wait_for_instance_profile_visible(iam, ec2_name)
    return svc_name, ec2_name


def _wait_for_role_visible(iam, role_name: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_for_instance_profile_visible(iam, profile_name: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
            if profile["Roles"]:
                return
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity" or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance profile {profile_name} never became visible with its role attached")
        time.sleep(interval_s)


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


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
            except ClientError as exc:
                # An in-flight update answers InvalidParameterValue ("invalid state"): retry it; raise the rest.
                if exc.response["Error"]["Code"] not in ("InvalidParameterValue", "OperationInProgressFailure"):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s}s")


def _retry_insufficient_privileges(fn, *, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
