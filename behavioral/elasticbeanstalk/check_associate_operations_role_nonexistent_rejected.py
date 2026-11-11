"""associate-operations-role-nonexistent-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "associate-operations-role-nonexistent-rejected"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole rejects a role ARN that does not exist with
    InvalidParameterValue (parameter validation, not the privileges check) and leaves
    OperationsRole unset, while a real, properly-trusted role on the same environment is accepted."""
    app_name = _create_app(ctx)
    # Before the environment, so its teardown runs AFTER the environment's (LIFO): Beanstalk
    # assumes the operations role to terminate, and deleting it first leaves the env unterminatable.
    trusted_role_arn = _create_operations_role(ctx)
    env_name = _create_ready_environment(ctx, app_name)
    eb = ctx.client("elasticbeanstalk")

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    nonexistent_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name(_EB_PREFIX + 'nosuchrole-')}"
    code, message = _error_code(
        lambda: eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=nonexistent_role_arn)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = f"Operations role ARN '{nonexistent_role_arn}' isn't valid. Specify an existing IAM role."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    def _current_ops_role() -> str | None:
        envs = eb.describe_environments(EnvironmentNames=[env_name]).get("Environments", [])
        return envs[0].get("OperationsRole") if envs else None

    assert not _current_ops_role(), "OperationsRole was set despite the association being rejected"

    # Positive control: a real role that trusts elasticbeanstalk.amazonaws.com is accepted.
    _associate_ops_role_with_retry(eb, env_name, trusted_role_arn)

    observed = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        observed = _current_ops_role()
        if observed == trusted_role_arn:
            break
        time.sleep(5.0)
    assert observed == trusted_role_arn, f"positive-control association never took effect, got {observed!r}"



# ===== helpers =====
_EB_PREFIX = "sim2real-eb-"


def _eb_name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_EB_PREFIX}{kind}-")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    python_stacks = [s for s in stacks if "Python" in s and "Amazon Linux 2" in s and "Docker" not in s]
    candidates = python_stacks or [s for s in stacks if "Python" in s] or stacks
    return candidates[-1]


def _create_app(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    app_name = _eb_name(ctx, "app")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    return app_name


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "ec2role")
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
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "svcrole")
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


def _create_operations_role(ctx: Any) -> str:
    """A role trusted by elasticbeanstalk.amazonaws.com - valid for the operations role association."""
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "opsrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )["Role"]
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


def _create_untrusted_role(ctx: Any) -> str:
    """A role that only trusts ec2.amazonaws.com - elasticbeanstalk.amazonaws.com cannot assume it."""
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "untrustedrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
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


def _associate_ops_role_with_retry(eb: Any, env_name: str, role_arn: str, attempts: int = 10, delay_s: float = 6.0) -> None:
    """IAM roles are eventually consistent - a just-created role may not yet be assumable by
    Elastic Beanstalk, so retry on InvalidParameterValue/InsufficientPrivilegesException."""
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



def _wait_for_env_status(
    ctx: Any, env_name: str, target_statuses: set[str], timeout_s: float = 900.0, interval_s: float = 15.0
) -> str:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {target_statuses} within {timeout_s}s (last={last_status})")


def _terminate_environment(ctx: Any, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Disassociate any operations role, then terminate and wait for Terminated, re-issuing each
    call while an in-flight update (e.g. a just-made role association) rejects it."""
    eb = ctx.client("elasticbeanstalk")
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


def _create_ready_environment(ctx: Any, app_name: str, extra_option_settings: list | None = None) -> str:
    eb = ctx.client("elasticbeanstalk")
    env_name = _eb_name(ctx, "env")
    stack = _pick_solution_stack(ctx)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
    ]
    if extra_option_settings:
        option_settings.extend(extra_option_settings)
    kwargs = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "SolutionStackName": stack,
        "OptionSettings": option_settings,
        "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    }
    _create_env_with_retry(eb, kwargs)
    ctx.on_cleanup(lambda: _terminate_environment(ctx, env_name))
    _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0, interval_s=15.0)
    return env_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
