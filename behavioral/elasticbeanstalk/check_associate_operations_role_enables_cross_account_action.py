"""associate-operations-role-enables-cross-account-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "associate-operations-role-enables-cross-account-action"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole attaches an IAM role to a live environment, and
    DescribeEnvironments reflects the OperationsRole ARN thereafter.
    """
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    # A freshly provisioned account has no default EB instance profile / service role, so both
    # must be created here rather than left to an ambient "aws-elasticbeanstalk-*" default --
    # otherwise the environment fails to launch and terminates before it is ever Ready.
    instance_profile_name = _create_instance_profile(ctx, iam)
    service_role_arn = _create_service_role(ctx, iam)
    # Before the environment, so its teardown runs AFTER the environment's (LIFO): Beanstalk
    # assumes the operations role to terminate, and deleting it first leaves the env unterminatable.
    role_arn = _create_operations_role(ctx, iam, trusted_service="elasticbeanstalk.amazonaws.com")

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile_name},
        ],
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: _terminate_and_wait(eb, env_name)))

    # AssociateEnvironmentOperationsRole rejects a not-yet-Ready environment
    # (InvalidParameterValue), so the environment must actually finish launching first.
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900.0)

    # A just-created role can take a few seconds to become assumable service-wide; EB answers
    # InvalidParameterValue or InsufficientPrivilegesException until IAM propagates it.
    _associate_with_retry(eb, env_name, role_arn, timeout_s=90.0)

    envs = eb.describe_environments(EnvironmentNames=[env_name])["Environments"]
    assert len(envs) == 1, f"expected exactly one environment named {env_name!r}, got {len(envs)}"
    assert envs[0].get("OperationsRole") == role_arn, (
        f"expected OperationsRole={role_arn!r} after associate, got {envs[0].get('OperationsRole')!r}"
    )


# ===== helpers =====


def _safe(fn) -> None:
    """Run one teardown call; only a not-found answer means already gone, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "NoSuchEntity" or (err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", ""))):
            raise


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _create_operations_role(ctx, iam, trusted_service: str) -> str:
    role_name = ctx.unique_name("sim2real-eb-opsrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trusted_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _create_instance_profile(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eb-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)))
    return role_name


def _create_service_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eb-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)))
    return role_arn


def _associate_with_retry(eb, env_name: str, role_arn: str, timeout_s: float, interval_s: float = 6.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("InvalidParameterValue", "InsufficientPrivilegesException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _wait_for_env_status(eb, env_name: str, statuses: set, timeout_s: float, interval_s: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"environment {env_name} did not reach {statuses} within {timeout_s}s "
        f"(last status={last['Status'] if last else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
