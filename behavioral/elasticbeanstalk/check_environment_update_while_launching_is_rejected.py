"""environment-update-while-launching-is-rejected."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-update-while-launching-is-rejected"
GROUP = 'environment-lifecycle'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn() expecting a ClientError; return its (Error.Code, Error.Message).

    Raises AssertionError when the call succeeds, so a missing refusal can never be read as a code.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


_TRANSIENT_STATUSES = ("Launching", "Updating", "Aborting", "LinkingFrom", "LinkingTo")


def _settle(eb, env_name, *, timeout_s=1200, interval_s=15.0):
    """Poll DescribeEnvironments until the environment leaves every transient status; return it.

    Raises AssertionError on timeout, so a truncated wait is never read as a settled state.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(
            EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments") or []
        last = envs[0] if envs else None
        if last is not None and last.get("Status") not in _TRANSIENT_STATUSES:
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"environment {env_name} did not leave {_TRANSIENT_STATUSES} within "
                f"{timeout_s}s; last record {last!r}")
        time.sleep(interval_s)


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

    # A just-created IAM role/instance-profile is not immediately visible to EB; retry the
    # create call itself (bounded, never a blind wait) until EB accepts it or the deadline passes.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = eb.create_environment(ApplicationName=app_name, EnvironmentName=env_name, **kwargs)
            break
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))
    return resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Launching environment refuses UpdateEnvironment until the pending operation finishes."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    # The check holds the in-progress window itself: the launch it just started runs for minutes,
    # and the refusal below is only meaningful while the record still reads Launching.
    resp = _launch_environment(ctx, eb, app_name)
    env_name = resp["EnvironmentName"]
    assert resp["Status"] == "Launching", f"a new environment must enter Launching, got {resp['Status']!r}"
    held = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    if held["Status"] != "Launching":
        raise AssertionError(
            f"precondition: the just-created {env_name} must still be launching, got {held['Status']!r}")

    code, message = _err(
        lambda: eb.update_environment(
            EnvironmentName=env_name,
            OptionSettings=[
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "FIDELITY_TEST_VAR",
                    "Value": "updated-value",
                }
            ],
        )
    )
    assert code == "InvalidParameterValue", (
        f"UpdateEnvironment against a Launching environment must be rejected with "
        f"InvalidParameterValue, got {code!r}"
    )
    expected = f"Environment named {env_name} is in an invalid state for this operation. Must be Ready."
    assert message == expected, (
        f"expected the refusal message {expected!r}, got {message!r}"
    )

    # The rejected update must not have leaked into the environment configuration.
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, EnvironmentName=env_name
    )["ConfigurationSettings"][0]
    leaked = [
        o for o in settings["OptionSettings"] if o["OptionName"] == "FIDELITY_TEST_VAR"
    ]
    assert leaked == [], (
        "a rejected UpdateEnvironment must not apply any of its option settings"
    )

    # The launch settles Ready and the refused setting is still absent from the settled environment.
    final = _settle(eb, env_name)
    assert final["Status"] == "Ready", (
        f"the launched environment must settle Ready, got {final['Status']!r}"
    )
    settled = eb.describe_configuration_settings(
        ApplicationName=app_name, EnvironmentName=env_name
    )["ConfigurationSettings"][0]
    assert not [o for o in settled["OptionSettings"] if o["OptionName"] == "FIDELITY_TEST_VAR"], (
        "the refused UpdateEnvironment setting must stay absent once the launch settles"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
