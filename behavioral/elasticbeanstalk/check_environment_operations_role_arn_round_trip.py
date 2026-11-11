"""environment-operations-role-arn-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-operations-role-arn-round-trip"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The exact IAM role ARN passed to AssociateEnvironmentOperationsRole is persisted
    byte-for-byte and returned unchanged (no case folding, truncation, or re-formatting) by
    subsequent DescribeEnvironments calls."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-ebarn-app-")
    env_name = _short_env_name(ctx, "ebarn")
    # mixed-case path component to catch any silent normalization
    role_name = ctx.unique_name("sim2real-EbOpsRole-")[-63:]

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    stack = _pick_solution_stack(ctx)
    _create_environment_with_iam_propagation_retry(
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        OptionSettings=_env_option_settings(ctx),
    )
    # Blocks until Terminated, and runs before the operations role's teardown (LIFO): Beanstalk
    # assumes that role to terminate, and deleting it first leaves the env unterminatable.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"environment entered {env['Status']} instead of Ready"

    def _associate():
        eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn)

    _retry_insufficient_privileges(_associate, timeout_s=60.0)

    described = _poll_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0],
        lambda e: "OperationsRole" in e,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert described.get("OperationsRole") == role_arn, (
        f"OperationsRole round-tripped as {described.get('OperationsRole')!r}, expected exact byte-for-byte "
        f"{role_arn!r}"
    )


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role a fresh account has no default
    for ("aws-elasticbeanstalk-ec2-role" / "aws-elasticbeanstalk-service-role" style principals),
    registering LIFO teardown. Returns (instance_profile|None, service_role|None); degrades to
    (None, None) if IAM is unreachable, letting the service fall back to its own defaults."""
    if hasattr(ctx, "_eb_iam"):
        return ctx._eb_iam
    iam = ctx.client("iam")
    try:
        iam.list_roles(MaxItems=1)
    except Exception:
        ctx._eb_iam = (None, None)
        return ctx._eb_iam

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        except Exception as exc:  # noqa: BLE001 -- already-exists is fine
            if "EntityAlreadyExists" not in str(exc):
                return False
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policy_arns:
            try:
                iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))
            except Exception:  # noqa: BLE001
                pass
        return True

    ec2_role = ctx.unique_name("sim2real-ebarn-ec2-role-")
    svc_role = ctx.unique_name("sim2real-ebarn-service-role-")
    profile = ctx.unique_name("sim2real-ebarn-ec2-profile-")
    ec2_ok = _create_role(
        ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"]
    )
    service_role = (
        svc_role
        if _create_role(
            svc_role,
            "elasticbeanstalk.amazonaws.com",
            [
                "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
                "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
            ],
        )
        else None
    )
    instance_profile = None
    if ec2_ok:
        made = True
        try:
            iam.create_instance_profile(InstanceProfileName=profile)
            ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
        except Exception as exc:  # noqa: BLE001
            if "EntityAlreadyExists" not in str(exc):
                made = False
        if made:
            try:
                iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                ctx.on_cleanup(
                    lambda: iam.remove_role_from_instance_profile(
                        InstanceProfileName=profile, RoleName=ec2_role
                    )
                )
            except Exception:  # noqa: BLE001
                pass
            instance_profile = profile
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _env_option_settings(ctx):
    """Baseline option settings that make a single-instance environment launch on an account
    with no default Elastic Beanstalk IAM principals."""
    instance_profile, service_role = _ensure_env_iam(ctx)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    if instance_profile:
        settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"}
        )
    return settings


def _create_environment_with_iam_propagation_retry(eb, *, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs):
    """CreateEnvironment can transiently reject a freshly created IAM role/instance profile before
    it is visible service-side; retry within a bounded window (IAM eventual consistency) instead of
    a fixed sleep, and surface anything else immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValue" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
    if predicate(value):
        return value
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


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
            except ClientError as err:
                # Refused while an in-flight update holds the environment, or already gone: retried
                # or settled by the next describe; anything else re-raises.
                if err.response["Error"]["Code"] not in ("InvalidParameterValue", "OperationInProgressFailure"):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s:.0f}s")


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
