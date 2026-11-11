"""associate-environment-operations-role-then-disassociate."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-environment-operations-role-then-disassociate"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]

_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole attaches a role visible on DescribeEnvironments,
    and DisassociateEnvironmentOperationsRole removes it cleanly."""
    eb = ctx.client("elasticbeanstalk")
    # Before the environment, so its teardown runs AFTER the environment's (LIFO): Beanstalk
    # assumes the operations role to terminate, and deleting it first leaves the env unterminatable.
    role_arn = _create_role(ctx, trust_service="elasticbeanstalk.amazonaws.com", policy_arn=_ADMIN_POLICY_ARN)
    env = _create_ready_environment(ctx)
    env_name = env["env_name"]

    _associate_ops_role_with_retry(eb, env_name, role_arn)
    attached = _poll_operations_role(ctx, env_name, timeout_s=90)
    assert attached == role_arn, f"expected OperationsRole {role_arn!r}, observed {attached!r}"

    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
    removed = _poll_operations_role_absent(ctx, env_name, timeout_s=90)
    assert removed, "OperationsRole was still present after DisassociateEnvironmentOperationsRole"


# ===== helpers =====

def _pick_solution_stack(eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("no solution stacks available in this region")
    return stacks[0]


def _env_name(ctx: Any) -> str:
    name = ctx.unique_name("eb-")
    return name[-40:] if len(name) > 40 else name


def _wait_for_env_status(ctx: Any, env_name: str, target_statuses: set, timeout_s: float = 900, interval_s: float = 15) -> str | None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    return last_status


def _create_eb_instance_profile(ctx: Any) -> str:
    """A fresh account has no default aws-elasticbeanstalk-ec2-role, so create one in-check
    rather than assume it is ambient."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebec2role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
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


def _create_eb_service_role(ctx: Any) -> str:
    """A fresh account has no default aws-elasticbeanstalk-service-role, so create one in-check
    rather than assume it is ambient."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebsvcrole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )["Role"]
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


def _create_env_with_retry(eb: Any, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
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


def _create_ready_environment(ctx: Any, option_settings: list | None = None, timeout_s: float = 900) -> dict[str, str]:
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-ebapp-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    env_name = _env_name(ctx)
    stack = _pick_solution_stack(eb)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
    ]
    if option_settings:
        settings.extend(option_settings)

    kwargs = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "SolutionStackName": stack,
        "OptionSettings": settings,
        "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    }
    _create_env_with_retry(eb, kwargs)
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))

    status = _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=timeout_s)
    if status != "Ready":
        raise AssertionError(f"environment {env_name} did not reach Ready, last status={status}")
    return {"app_name": app_name, "env_name": env_name}


def _create_role(ctx: Any, *, trust_service: str, policy_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebrole-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": trust_service},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    # Poll for read-after-write consistency of the freshly created role.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role_arn


def _associate_ops_role_with_retry(eb: Any, env_name: str, role_arn: str, attempts: int = 10, delay_s: float = 6.0) -> None:
    """A freshly-Ready environment can still reject AssociateEnvironmentOperationsRole with
    InvalidParameterValue/InsufficientPrivilegesException for a short window after launch, so retry
    on those codes rather than treat the first attempt as final."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterValue", "InsufficientPrivilegesException"):
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _poll_operations_role(ctx: Any, env_name: str, timeout_s: float = 90, interval_s: float = 3) -> str | None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name]).get("Environments", [])
        if envs:
            last = envs[0].get("OperationsRole")
            if last:
                return last
        time.sleep(interval_s)
    return last


def _poll_operations_role_absent(ctx: Any, env_name: str, timeout_s: float = 90, interval_s: float = 3) -> bool:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name]).get("Environments", [])
        if envs and not envs[0].get("OperationsRole"):
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

