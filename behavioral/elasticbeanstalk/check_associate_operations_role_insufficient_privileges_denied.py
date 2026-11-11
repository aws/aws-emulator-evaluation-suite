"""associate-operations-role-insufficient-privileges-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-operations-role-insufficient-privileges-denied"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole does not check the role's trust policy: a role trusted
    only by ec2.amazonaws.com is accepted and read back as OperationsRole, and associating a
    correctly-trusted role afterward replaces it."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    # A launched environment needs its own EC2 instance profile and EB service role: a fresh
    # account has neither of the default `aws-elasticbeanstalk-*` roles the console would create.
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)

    stack = _pick_solution_stack(eb)
    _create_environment_with_retry(
        eb,
        dict(
            ApplicationName=app_name,
            EnvironmentName=env_name,
            SolutionStackName=stack,
            OptionSettings=[
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
            ],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ),
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, {"Ready"})

    # A role trusted only by EC2 cannot be passed to Elastic Beanstalk as an operations role.
    untrusted_role_arn = _create_operations_role(ctx, trusted_service="ec2.amazonaws.com")
    # Re-registered after each operations role so it runs before that role's teardown (LIFO):
    # Beanstalk assumes the operations role to terminate, and deleting it first leaves the env
    # unterminatable. The roles stay created here, after Ready, as the check always did.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_for_role_assumable(ctx.client("iam"), untrusted_role_arn)

    _associate_ops_role_with_retry(eb, env_name, untrusted_role_arn)
    _wait_env_status(eb, env_name, {"Ready"})
    envs = eb.describe_environments(EnvironmentNames=[env_name])["Environments"]
    actual_role = envs[0].get("OperationsRole")
    assert actual_role == untrusted_role_arn, (
        f"expected the EC2-trusted role {untrusted_role_arn!r} to be accepted as OperationsRole, got {actual_role!r}"
    )

    # Positive control, same file: a correctly-trusted role associates successfully. A just-created
    # role's trust policy is eventually consistent from Elastic Beanstalk's point of view, so retry
    # the transient InvalidParameterValue/InsufficientPrivilegesException rather than treat it as
    # the target contract under test (that is the untrusted-role call above, already asserted).
    trusted_role_arn = _create_operations_role(ctx, trusted_service="elasticbeanstalk.amazonaws.com")
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_for_role_assumable(ctx.client("iam"), trusted_role_arn)
    _associate_ops_role_with_retry(eb, env_name, trusted_role_arn)
    # The association itself deploys the role to the environment (a real config update, not just a
    # metadata write), so wait for it to settle back to Ready -- both so the terminal read below
    # observes the converged state, and so cleanup's terminate_environment isn't rejected for an
    # update still in progress.
    _wait_env_status(eb, env_name, {"Ready"})
    envs = eb.describe_environments(EnvironmentNames=[env_name])["Environments"]
    actual_role = envs[0].get("OperationsRole")
    assert actual_role == trusted_role_arn, (
        f"expected OperationsRole {trusted_role_arn!r} after the positive-control association, got {actual_role!r}"
    )


# ===== helpers =====


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _create_eb_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)))
    return role_name


def _create_eb_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)))
    return resp["Role"]["Arn"]


def _create_environment_with_retry(eb, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            eb.create_environment(**kwargs)
            return
        except ClientError as err:
            # The service role/instance profile just created may not have propagated yet.
            if err.response["Error"]["Code"] == "InsufficientPrivilegesException":
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _create_operations_role(ctx, trusted_service: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-opsrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trusted_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _associate_ops_role_with_retry(eb, env_name: str, role_arn: str, attempts: int = 10, delay_s: float = 6.0) -> None:
    """A just-created role's trust policy is eventually consistent from Elastic Beanstalk's point
    of view, so retry the transient InvalidParameterValue/InsufficientPrivilegesException."""
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
    raise last_err


def _wait_env_status(eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name])["Environments"]
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return
        if last is not None and last["Status"] == "Terminated" and "Terminated" not in statuses:
            raise AssertionError(f"environment {env_name} terminated instead of reaching {statuses} (last={last!r})")
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r})")


def _wait_for_role_assumable(iam, role_arn: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    role_name = role_arn.split("/")[-1]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(interval_s)
    return


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
