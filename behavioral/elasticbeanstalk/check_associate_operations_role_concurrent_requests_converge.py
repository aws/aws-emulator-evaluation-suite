"""associate-operations-role-concurrent-requests-converge."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "associate-operations-role-concurrent-requests-converge"
GROUP = "concurrency"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateEnvironmentOperationsRole calls with different valid roles converge
    to exactly one of the two roles, and the environment's Status is untouched by the race."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-behav-race-")
    env_name = ctx.unique_name("sim2real-race-")

    role_arns = []
    for i in range(2):
        role_name = ctx.unique_name(f"sim2real-eb-race-{i}-")[:64]
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "elasticbeanstalk.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }
        arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
        ctx.on_cleanup(lambda rn=role_name: iam.delete_role(RoleName=rn))
        iam.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
        )
        ctx.on_cleanup(
            lambda rn=role_name: iam.detach_role_policy(
                RoleName=rn, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
            )
        )
        _wait_for_role_visible(iam, role_name)
        role_arns.append(arn)

    # Provisioned, with cleanup registered, before create_application: teardown is LIFO, so the
    # environment is terminated before these roles are deleted out from under it.
    ec2_profile_name, svc_role_name = _provision_eb_launch_iam(ctx, iam)

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        ],
    )
    # Registered after the operations roles so it runs first (LIFO) and blocks until Terminated:
    # Beanstalk assumes the operations role to terminate, and deleting it first leaves the env
    # unterminatable. TerminateEnvByForce above is fire-and-forget and does not wait.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)

    def associate(role_arn: str):
        return _associate_role_with_retry(eb, env_name, role_arn, timeout_s=_budget_s(ctx, 60.0),
                                          ctx=ctx)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(associate, arn) for arn in role_arns]
        results = [f.result() for f in futures]

    assert all(r is None for r in results), (
        f"a racer call raised instead of returning cleanly: results={results!r}"
    )

    # The association may be applied asynchronously: wait for it to land before sampling stability.
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
        settled = (env.get("OperationsRole"), env["Status"])
        if settled[0] in role_arns and settled[1] == "Ready":
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"environment {env_name} settling on a racer's role: the run "
                                   f"budget ended first; not graded")
            raise AssertionError(
                f"after the race the environment never settled on one racer's role with Status "
                f"'Ready': last OperationsRole={settled[0]!r} Status={settled[1]!r}, expected one of "
                f"{role_arns}"
            )
        time.sleep(1.0)

    observed = [settled]
    for _ in range(3):
        time.sleep(1.5)
        env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
        observed.append((env.get("OperationsRole"), env["Status"]))

    final_role, final_status = observed[-1]
    assert final_role in role_arns, (
        f"converged OperationsRole={final_role!r} is neither racer's role -- expected one of {role_arns}"
    )
    assert all(r == final_role for r, _ in observed), (
        f"OperationsRole flapped across repeated independent reads: {observed}"
    )
    assert final_status == "Ready", (
        f"environment Status={final_status!r} != 'Ready' after the race settled; observed={observed}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_env_status(eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 2.0,
                         ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"environment {env_name} reaching {statuses}: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"environment {env_name} never reached {statuses}; last={last}")


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


def _provision_eb_launch_iam(ctx, iam) -> tuple[str, str]:
    """A fresh account has no default EB EC2/service roles (only the console creates them), so
    CreateEnvironment needs an explicit instance profile and service role or it never launches.
    Returns (instance_profile_name, service_role_name)."""
    ec2_role_name = ctx.unique_name("sim2real-eb-race-ec2-")[:64]
    svc_role_name = ctx.unique_name("sim2real-eb-race-svc-")[:64]
    profile_name = ctx.unique_name("sim2real-eb-race-prof-")[:128]

    ec2_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=json.dumps(ec2_trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role_name))
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    )
    _wait_for_role_visible(iam, ec2_role_name)

    svc_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=svc_role_name, AssumeRolePolicyDocument=json.dumps(svc_trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_role_name, PolicyArn=p))
    _wait_for_role_visible(iam, svc_role_name)

    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name))

    return profile_name, svc_role_name


def _wait_for_role_visible(iam, role_name: str, timeout_s: float = 30.0, interval_s: float = 1.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(interval_s)
    raise AssertionError(f"role {role_name} never became visible")


def _associate_role_with_retry(eb, env_name: str, role_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0,
                               ctx=None) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn)
            return None
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                if (err.response["Error"]["Code"] == "InsufficientPrivilegesException"
                        and ctx is not None and _budget_spent(ctx)):
                    raise TimeoutError(f"{role_arn} becoming usable by Elastic Beanstalk: the run "
                                       f"budget ended first; not graded") from err
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
