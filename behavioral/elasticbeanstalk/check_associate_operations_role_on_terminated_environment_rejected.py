"""associate-operations-role-on-terminated-environment-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "associate-operations-role-on-terminated-environment-rejected"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """AssociateEnvironmentOperationsRole succeeds on a live environment and Disassociate clears it,
    but once the environment is terminated a re-associate is rejected and the environment keeps
    no OperationsRole and stays Terminated."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    resource_tags = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]

    app_name = ctx.unique_name("sim2real-eb6-app-")
    env_name = ctx.unique_name("sim2real-eb6-env-")

    eb.create_application(ApplicationName=app_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    role_name = ctx.unique_name("sim2real-eb6-ops-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=resource_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _wait_for_role_gettable(iam, role_name, timeout_s=30.0)

    # A fresh account has no default EB service role / instance profile, and letting EB try
    # to auto-provision them on CreateEnvironment is not reliable (observed: the environment
    # goes straight to Terminated within seconds, with no exception raised from the create
    # call itself) - so create both explicitly, as the account's own launch prerequisites.
    instance_profile_name = _create_eb_instance_profile(ctx, resource_tags)
    service_role_arn = _create_eb_service_role(ctx, resource_tags)

    _create_env_with_retry(
        eb,
        dict(
            ApplicationName=app_name,
            EnvironmentName=env_name,
            SolutionStackName=_pick_solution_stack(ctx),
            OptionSettings=[
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile_name},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
            ],
            Tags=resource_tags,
        ),
    )
    # Blocks until Terminated, and runs before the operations role's teardown (LIFO): Beanstalk
    # assumes that role to terminate, and deleting it first leaves the env unterminatable.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0, fail_statuses={"Terminated"})

    # Positive control: association succeeds on a live, Ready environment. IAM roles are
    # eventually consistent, so retry on the same InvalidParameterValue a too-fresh role trips.
    _associate_with_retry(eb, env_name, role_arn)
    associated = _wait_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0],
        lambda e: e.get("OperationsRole") == role_arn,
        timeout_s=120.0,
    )
    assert associated["OperationsRole"] == role_arn, (
        f"positive control: expected OperationsRole {role_arn!r}, observed {associated.get('OperationsRole')!r}"
    )

    # Prove disassociation too, so the environment enters termination with OperationsRole
    # unset - a baseline that WOULD change if the post-termination rejection below silently
    # took effect instead of being refused.
    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
    cleared = _wait_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0],
        lambda e: not e.get("OperationsRole"),
        timeout_s=120.0,
    )
    assert not cleared.get("OperationsRole"), (
        f"disassociate did not clear OperationsRole, still observed {cleared.get('OperationsRole')!r}"
    )

    eb.terminate_environment(EnvironmentName=env_name)
    _wait_env_status(ctx, env_name, {"Terminated"}, timeout_s=600.0)

    # Break exactly one thing: associate again, now that the environment is terminated.
    code, message = _error_code(lambda: eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message!r})"
    expected = f"No Environment found for EnvironmentName = '{env_name}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the terminated environment's state did not change because of the
    # rejected call - OperationsRole is still unset (it was cleared above, and would read
    # back as role_arn if the rejected call had silently taken effect) and Status is still
    # Terminated.
    unaffected = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"][0]
    assert not unaffected.get("OperationsRole"), (
        f"OperationsRole became {unaffected.get('OperationsRole')!r} despite the association being rejected"
    )
    assert unaffected["Status"] == "Terminated", f"expected Status Terminated, got {unaffected['Status']!r}"


# ===== helpers =====

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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_role_gettable(iam, role_name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(interval_s)


def _associate_with_retry(eb, env_name: str, role_arn: str, attempts: int = 10, delay_s: float = 6.0) -> None:
    """IAM roles are eventually consistent - a just-created role may not yet be assumable by
    Elastic Beanstalk, so retry on InvalidParameterValue/InsufficientPrivilegesException."""
    from botocore.exceptions import ClientError

    last_err: Exception | None = None
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
    assert last_err is not None, "unreachable: loop exited without a stored ClientError"
    raise last_err


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    matches = [s for s in stacks if "Node.js" in s and "Docker" not in s]
    if not matches:
        raise AssertionError("no Node.js (non-Docker) solution stack available in this region")
    return matches[0]


def _wait_until(probe, predicate, timeout_s: float, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last observed={last!r}")


def _wait_env_status(ctx, env_name: str, target_statuses: set, timeout_s: float, fail_statuses: set = frozenset()):
    """Poll DescribeEnvironments until Status lands in target_statuses. Raises immediately
    (rather than burning the full timeout) if Status instead lands in fail_statuses - e.g. a
    launch that failed and went straight to Terminated while waiting for Ready."""
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"][0]
        status = last.get("Status")
        if status in target_statuses:
            return last
        if status in fail_statuses:
            raise AssertionError(
                f"environment reached {status!r} (wanted one of {target_statuses}); last observed={last!r}"
            )
        time.sleep(2)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {target_statuses}; last observed={last!r}")


def _create_eb_instance_profile(ctx, resource_tags: list) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb6-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))
    _wait_for_role_gettable(iam, role_name, timeout_s=30.0)
    return role_name


def _create_eb_service_role(ctx, resource_tags: list) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb6-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=resource_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda policy_arn=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _wait_for_role_gettable(iam, role_name, timeout_s=30.0)
    return role_arn


def _create_env_with_retry(eb, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    """The freshly created service/instance role above may not yet be assumable by Elastic
    Beanstalk (IAM eventual consistency), so retry CreateEnvironment on InsufficientPrivilegesException."""
    from botocore.exceptions import ClientError

    last_err: Exception | None = None
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
    assert last_err is not None, "unreachable: loop exited without a stored ClientError"
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
