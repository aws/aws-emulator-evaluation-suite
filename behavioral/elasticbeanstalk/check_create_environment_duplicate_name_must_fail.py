"""create-environment-duplicate-name-must-fail."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-environment-duplicate-name-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_STACK_CACHE = []

def _solution_stack(eb):
    """A usable SolutionStackName, preferring a current AL2023 Docker/Python stack."""
    if not _STACK_CACHE:
        _STACK_CACHE.extend(eb.list_available_solution_stacks().get("SolutionStacks") or [])
    stacks = list(_STACK_CACHE)
    if not stacks:
        raise AssertionError("No solution stacks available from ListAvailableSolutionStacks")
    preferred = (
        [s for s in stacks if "Amazon Linux 2023" in s and "running Docker" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s]
        or [s for s in stacks if "running Docker" in s]
    )
    return (preferred or stacks)[0]


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment needs,
    registering LIFO teardown. Returns (instance_profile|None, service_role|None); degrades
    to (None, None) when IAM is unreachable (an emulator that does not serve IAM), letting the
    service apply its defaults. Memoized on ctx so an env-creating check provisions IAM once."""
    if hasattr(ctx, "_eb_iam"):
        return ctx._eb_iam
    try:
        iam = ctx.client("iam")
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
        except Exception as exc:  # noqa: BLE001 — already-exists is fine
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

    ec2_role = ctx.unique_name("sim2real-behav-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-behav-eb-service-role-")
    profile = ctx.unique_name("sim2real-behav-eb-ec2-profile-")
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
    """Baseline option settings that make a single-instance environment launch."""
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


def _create_environment_with_iam_retry(eb, deadline_s=45, interval_s=5, **kwargs):
    """Bounded retry around CreateEnvironment for the one failure IAM eventual consistency can
    actually cause here: EB rejecting the freshly-created instance profile/service role as
    unknown. Any other error surfaces immediately — this must not mask a real defect."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = err.get("Message", "")
            is_iam_race = err.get("Code") == "InvalidParameterValue" and (
                "nstance profile" in msg or "not usable" in msg or "oleName" in msg or "ole ARN" in msg
            )
            if not is_iam_race or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _launch_environment(ctx, eb, app_name, **kwargs):
    """Create an environment with the baseline (IAM-aware) option settings merged under any
    caller-supplied OptionSettings; register TerminateEnvironment teardown."""
    env_name = kwargs.pop("EnvironmentName", None) or ctx.unique_name("sim2real-behav-eb-env-")
    if "SolutionStackName" not in kwargs and "PlatformArn" not in kwargs and "TemplateName" not in kwargs:
        kwargs["SolutionStackName"] = _solution_stack(eb)
    merged = {(o["Namespace"], o["OptionName"]): o for o in _env_option_settings(ctx)}
    for o in kwargs.pop("OptionSettings", []):
        merged[(o["Namespace"], o["OptionName"])] = o
    kwargs["OptionSettings"] = list(merged.values())
    kwargs.setdefault("Tags", [{"Key": "sim2real", "Value": "true"}])
    resp = _create_environment_with_iam_retry(
        eb, ApplicationName=app_name, EnvironmentName=env_name, **kwargs
    )
    ctx.on_cleanup(lambda: _terminate_when_settled(eb, env_name))
    return resp

def _terminate_when_settled(eb, env_name, timeout_s=1500.0, interval_s=15.0):
    """TerminateEnvironment refuses an environment that is still launching, so wait for it to
    settle at Ready, terminate it, and wait for Terminated so the application delete that runs
    after this succeeds. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    terminated = False
    status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)[
            "Environments"
        ]
        status = envs[0]["Status"] if envs else "Terminated"
        if status == "Terminated":
            return
        if status == "Ready" and not terminated:
            eb.terminate_environment(EnvironmentName=env_name)
            terminated = True
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name!r} never reached Terminated; last status {status!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment must refuse to reuse the name of an existing live environment."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    resp = _launch_environment(ctx, eb, app_name)
    env_name = resp["EnvironmentName"]
    env_id = resp["EnvironmentId"]

    code, message = _err(
        lambda: eb.create_environment(
            ApplicationName=app_name,
            EnvironmentName=env_name,
            SolutionStackName=_solution_stack(eb),
            OptionSettings=_env_option_settings(ctx),
        )
    )
    assert code == "InvalidParameterValue", (
        f"reusing a live environment name must fail with InvalidParameterValue, got {code!r}"
    )
    expected = f"Environment {env_name} already exists."
    assert message == expected, (
        f"reusing a live environment name must say {expected!r}, got {message!r}"
    )

    envs = eb.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"]
    assert len(envs) == 1, "the rejected duplicate must not create a second environment"
    assert envs[0]["EnvironmentId"] == env_id, (
        f"the surviving environment must be the original, expected id {env_id!r}, "
        f"got {envs[0]['EnvironmentId']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
