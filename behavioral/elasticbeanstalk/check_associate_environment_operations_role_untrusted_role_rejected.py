"""associate-environment-operations-role-untrusted-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-environment-operations-role-untrusted-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole rejects a nonexistent role with InvalidParameterValue
    and keeps OperationsRole, but accepts an existing role whose trust policy omits Beanstalk:
    existence, not trust, gates the call."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-beh-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    trusted_role_name, trusted_role_arn = _create_role(
        ctx, iam, "sim2real-ebtrusted-", trust_services=["elasticbeanstalk.amazonaws.com"]
    )
    untrusted_role_name, untrusted_role_arn = _create_role(
        ctx, iam, "sim2real-ebuntrust-", trust_services=["ec2.amazonaws.com"]
    )

    # A fresh account has no default EB instance profile or service role; an environment
    # launched without them rolls back to Terminated within seconds.
    instance_profile = _create_eb_instance_profile(ctx, iam)
    service_role_arn = _create_eb_service_role(ctx, iam)

    env_name = ctx.unique_name("sim2real-env-")[:40]
    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        ],
    )
    # Blocks until Terminated, and runs before the operations roles' teardown (LIFO): Beanstalk
    # assumes the role to terminate, and deleting it first leaves the env unterminatable.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, {"Ready"}, timeout_s=900, interval_s=15, include_deleted=True, app_name=app_name)

    # Positive control: a role trusted by elasticbeanstalk.amazonaws.com associates cleanly.
    _associate_with_retry(eb, env_name, trusted_role_arn)
    env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert env.get("OperationsRole") == trusted_role_arn, (
        f"expected the trusted role to associate; OperationsRole={env.get('OperationsRole')!r}"
    )

    # Break one thing: a role identifier that names no real IAM role.
    account_id = trusted_role_arn.split(":")[4]
    nonexistent_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-eb-never-created-role"
    code, message = _error_code(lambda: eb.associate_environment_operations_role(
        EnvironmentName=env_name, OperationsRole=nonexistent_role_arn
    ))
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for an OperationsRole naming no real IAM role, got {code!r}"
    )
    expected = f"Operations role ARN '{nonexistent_role_arn}' isn't valid. Specify an existing IAM role."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected call must not have displaced the previously-associated role.
    env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert env.get("OperationsRole") == trusted_role_arn, (
        f"a rejected AssociateEnvironmentOperationsRole must not change OperationsRole; "
        f"got {env.get('OperationsRole')!r}"
    )

    # An existing role that elasticbeanstalk.amazonaws.com cannot assume still associates.
    _associate_with_retry(eb, env_name, untrusted_role_arn)
    env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert env.get("OperationsRole") == untrusted_role_arn, (
        f"a role that exists (even if untrusted by the service) should associate; "
        f"got {env.get('OperationsRole')!r}"
    )


# ===== helpers =====

def _error_code(fn):
    """Return the (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    python_stacks = [s for s in stacks if "Python" in s and "Amazon Linux 2" in s and "Docker" not in s]
    candidates = python_stacks or [s for s in stacks if "Windows" not in s] or stacks
    return candidates[-1]


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=15.0, include_deleted=False, app_name=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=include_deleted)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return last
        time.sleep(interval_s)
    diag = ""
    if app_name is not None:
        all_envs = eb.describe_environments(ApplicationName=app_name, IncludeDeleted=True).get("Environments", [])
        diag = f" all environments under {app_name!r}: {[(e.get('EnvironmentName'), e.get('Status'), e.get('Health')) for e in all_envs]!r}"
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r}).{diag}")


def _terminate_and_wait(eb, env_name, timeout_s=600.0, interval_s=2.0):
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


def _delete_application(eb, app_name):
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)


def _create_eb_instance_profile(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-ebec2role-")
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


def _create_eb_service_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-ebsvcrole-")
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


def _create_role(ctx, iam, prefix: str, trust_services: list[str]):
    role_name = ctx.unique_name(prefix)
    principal = trust_services[0] if len(trust_services) == 1 else trust_services
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role = iam.get_role(RoleName=role_name)["Role"]
    return role_name, role["Arn"]


def _delete_role(iam, role_name: str) -> None:
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _associate_with_retry(eb, env_name: str, role_arn: str, attempts: int = 10, delay_s: float = 6.0) -> None:
    """IAM changes (a just-created role, a just-updated trust policy) are eventually consistent,
    so retry on the same transient codes an inconsistent view of the role would produce."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
