"""concurrent-associate-disassociate-operations-role-converges."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-disassociate-operations-role-converges"
GROUP = "concurrency"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing Associate/DisassociateEnvironmentOperationsRole calls all succeed, and once settled
    repeated DescribeEnvironments report the same OperationsRole (the role ARN or absent)."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    svc_role_name, _svc_role_arn, ec2_profile_name = _create_eb_roles(ctx)
    ops_role_arn = _create_role_trusting(ctx, "elasticbeanstalk.amazonaws.com")
    solution_stack = _pick_solution_stack(eb)
    _create_environment(ctx, eb, app_name, env_name, svc_role_name, ec2_profile_name, solution_stack_name=solution_stack)
    # Registered after the operations role so it runs first (LIFO) and blocks until Terminated:
    # Beanstalk assumes the operations role to terminate, and deleting it first leaves the env
    # unterminatable. TerminateEnvByForce above is fire-and-forget and does not wait.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, targets={"Ready"}, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)

    # EB can reject a just-created role that IAM already reports visible (InvalidParameterValue /
    # InsufficientPrivilegesException); one retried associate/disassociate cycle absorbs that
    # window before the race, so propagation flake is not mistaken for the invariant under test.
    _retry_iam_propagation(
        lambda: eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=ops_role_arn)
    )
    # Each priming call must take effect on a separate read, so a target ignoring both fails.
    _wait_operations_role(ctx, eb, env_name, ops_role_arn)
    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
    _wait_operations_role(ctx, eb, env_name, None)

    def _associate() -> tuple[str, str | None]:
        try:
            eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=ops_role_arn)
            return "associate", None
        except ClientError as err:
            return "associate", err.response["Error"]["Code"]

    def _disassociate() -> tuple[str, str | None]:
        try:
            eb.disassociate_environment_operations_role(EnvironmentName=env_name)
            return "disassociate", None
        except ClientError as err:
            return "disassociate", err.response["Error"]["Code"]

    calls = [_associate, _disassociate, _associate, _disassociate, _associate, _disassociate]
    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        results = [f.result() for f in [pool.submit(c) for c in calls]]

    for kind, code in results:
        assert code is None, f"unexpected error during racing {kind}: {code}"

    def _read() -> tuple[Any, str]:
        env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
        return env.get("OperationsRole"), env["Status"]

    # The racers' effects may land asynchronously: settle on two consecutive agreeing reads of a
    # Ready environment before sampling stability.
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    previous = _read()
    while True:
        time.sleep(1.0)
        current = _read()
        if current == previous and current[1] == "Ready":
            break
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"OperationsRole on {env_name} settling after the race: the run "
                               f"budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"OperationsRole never settled after the racing calls: last two reads {previous!r} "
            f"then {current!r}"
        )
        previous = current

    observed: list[Any] = [current[0]]
    for _ in range(5):
        time.sleep(1.5)
        observed.append(_read()[0])

    final = observed[-1]
    assert final in (ops_role_arn, None), f"unexpected converged OperationsRole value: {final}"
    assert all(v == final for v in observed), f"OperationsRole flapped across repeated describes: {observed}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_operations_role(ctx, eb, env_name: str, expected: str | None, cap_s: float = 120.0) -> None:
    """Poll DescribeEnvironments until OperationsRole equals `expected` (None = absent)."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
        observed = env.get("OperationsRole") or None
        if observed == expected:
            return
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"OperationsRole on {env_name} becoming {expected!r}: the run "
                               f"budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"OperationsRole after the priming call: expected {expected!r}, got {observed!r}"
        )
        time.sleep(1.0)


def _retry_iam_propagation(fn, attempts: int = 30, delay_s: float = 2.0) -> None:
    last_err: ClientError | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterValue", "InsufficientPrivilegesException"):
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _create_eb_roles(ctx) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-ebrole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

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

    svc_role_arn = iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust)["Role"]["Arn"]
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

    # Bound the wait on IAM's own read-after-write consistency instead of sleeping blind:
    # poll until both roles and the instance profile (with its role attached) are readable.
    # Elastic Beanstalk's own eventual-consistency window for *assuming/passing* these roles
    # is separately covered by the InsufficientPrivilegesException retry in _create_environment.
    _wait_iam_visible(iam, lambda: iam.get_role(RoleName=svc_name))
    _wait_iam_visible(iam, lambda: iam.get_role(RoleName=ec2_name))
    _wait_iam_visible(
        iam,
        lambda: _require(iam.get_instance_profile(InstanceProfileName=ec2_name)["InstanceProfile"]["Roles"]),
    )
    return svc_name, svc_role_arn, ec2_name


def _wait_iam_visible(iam, probe, timeout_s: float = 30.0, interval_s: float = 1.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            probe()
            return
        except Exception as err:  # noqa: BLE001 - IAM read-after-write consistency, retried below
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"IAM object never became readable within {timeout_s}s: {last_err}")


def _require(value):
    if not value:
        raise AssertionError("expected value not yet visible")
    return value


def _create_role_trusting(ctx, principal: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ebops-")
    trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}
    )
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    _wait_iam_visible(iam, lambda: iam.get_role(RoleName=name))
    return role["Arn"]


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for stack in stacks:
        if "Amazon Linux 2" in stack and "Docker" not in stack and "Windows" not in stack:
            return stack
    return stacks[0]


def _create_environment(
    ctx,
    eb,
    app_name: str,
    env_name: str,
    svc_role_name: str,
    ec2_profile_name: str,
    solution_stack_name: str | None = None,
    platform_arn: str | None = None,
    extra_options: list[dict[str, str]] | None = None,
):
    options = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
    ]
    if extra_options:
        options.extend(extra_options)
    kwargs: dict[str, Any] = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "OptionSettings": options,
        "Tags": [{"Key": "sim2real", "Value": "true"}],
    }
    if platform_arn:
        kwargs["PlatformArn"] = platform_arn
    else:
        kwargs["SolutionStackName"] = solution_stack_name

    deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"environment {env_name} creation outlasting role propagation: "
                                       f"the run budget ended first; not graded") from err
                raise
            time.sleep(2)


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


def _wait_env_status(eb, env_name: str, targets: set[str], timeout_s: float = 900.0, interval_s: float = 2.0,
                     ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    status = last.get("Status") if last else None
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"environment {env_name} reaching {targets}: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
