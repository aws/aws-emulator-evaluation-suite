"""disassociate-operations-role-clears-it."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "disassociate-operations-role-clears-it"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateEnvironmentOperationsRole removes a previously associated role so
    DescribeEnvironments no longer reports it.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    instance_profile = _create_instance_profile(ctx)
    # Before the environment, so its teardown runs AFTER the environment's (LIFO): Beanstalk
    # assumes the operations role to terminate, and deleting it first leaves the env unterminatable.
    role_arn = _create_operations_role(ctx, trusted_service="elasticbeanstalk.amazonaws.com")
    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        ],
    )
    ctx.on_cleanup(lambda: _safe(lambda: _terminate_and_wait(eb, env_name)))
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=1200.0)

    _wait_for_role_assumable(ctx.client("iam"), role_arn)

    _associate_ops_role_with_retry(eb, env_name, role_arn)
    envs = eb.describe_environments(EnvironmentNames=[env_name])["Environments"]
    assert envs[0].get("OperationsRole") == role_arn, "setup: role association did not take effect"

    eb.disassociate_environment_operations_role(EnvironmentName=env_name)

    envs = eb.describe_environments(EnvironmentNames=[env_name])["Environments"]
    assert len(envs) == 1, f"expected exactly one environment for {env_name!r}, got {len(envs)}"
    cleared = envs[0].get("OperationsRole")
    assert not cleared, f"expected OperationsRole cleared after disassociate, still reported {cleared!r}"


# ===== helpers =====


def _safe(fn) -> None:
    """Run one teardown call; only a not-found answer means already gone, anything else raises."""
    from botocore.exceptions import ClientError
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


def _create_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
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
    # ctx.on_cleanup runs LIFO, so register in the reverse of the teardown order AWS requires:
    # unlink from the instance profile and detach the policy before the profile/role can be deleted.
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)))
    return role_name


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
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _terminate_and_wait(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Disassociate any operations role, then terminate and wait for Terminated, re-issuing each
    call while an in-flight update (e.g. a just-made role association) rejects it."""
    from botocore.exceptions import ClientError
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


def _wait_for_env_status(eb, env_name: str, target_statuses: set[str], timeout_s: float = 900.0, interval_s: float = 15.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {target_statuses} within {timeout_s}s (last={last_status})")


def _associate_ops_role_with_retry(eb, env_name: str, role_arn: str, attempts: int = 10, delay_s: float = 6.0) -> None:
    """IAM roles are eventually consistent from Elastic Beanstalk's perspective - a just-created
    role can still be rejected as "isn't valid" for a few seconds, so retry on InvalidParameterValue
    and InsufficientPrivilegesException."""
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
