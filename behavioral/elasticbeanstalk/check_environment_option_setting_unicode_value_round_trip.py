"""environment-option-setting-unicode-value-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "environment-option-setting-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]

_UNICODE_VALUE = "caf\u00e9 \u4e16\u754c \U0001f600 \u03a9 \u2764\ufe0f\u200d\U0001f525"
_NAMESPACE = "aws:elasticbeanstalk:application:environment"
_OPTION_NAME = "UNICODE_MARKER"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A unicode/emoji option value written via UpdateEnvironment round-trips byte-identical."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(ctx)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        {"Namespace": _NAMESPACE, "OptionName": _OPTION_NAME, "Value": "placeholder-ascii"},
    ]
    instance_profile, service_role = _ensure_env_iam(ctx)
    if instance_profile:
        option_settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        option_settings.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )
        option_settings.append(
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"}
        )
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=option_settings,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))

    _wait_for_environment_status(ctx, env_name, "Ready", timeout_s=1200)

    eb.update_environment(
        EnvironmentName=env_name,
        OptionSettings=[{"Namespace": _NAMESPACE, "OptionName": _OPTION_NAME, "Value": _UNICODE_VALUE}],
    )
    _wait_for_environment_status(ctx, env_name, "Ready", timeout_s=1200)

    settings = eb.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)
    option_settings = settings["ConfigurationSettings"][0]["OptionSettings"]
    matches = [
        o for o in option_settings if o["Namespace"] == _NAMESPACE and o["OptionName"] == _OPTION_NAME
    ]
    assert len(matches) == 1, f"expected exactly one {_OPTION_NAME} option, found {len(matches)}"
    assert matches[0]["Value"] == _UNICODE_VALUE, (
        f"unicode option value not byte-identical: got {matches[0]['Value']!r} expected {_UNICODE_VALUE!r}"
    )


def _ensure_env_iam(ctx: Any):
    """Best-effort: create the instance profile + service role a real EB environment needs to
    ever leave Launching, registering LIFO teardown. Returns (instance_profile|None,
    service_role|None); degrades to (None, None) when IAM is unreachable (an emulator that does
    not serve IAM), letting the service apply its defaults."""
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

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-service-role-")
    profile = ctx.unique_name("sim2real-eb-ec2-profile-")
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
    if instance_profile:
        # IAM is eventually consistent: wait until the profile it just created is itself
        # readable back, rather than sleeping a fixed guess at EB's own propagation delay.
        deadline = time.monotonic() + 60.0
        while True:
            try:
                iam.get_instance_profile(InstanceProfileName=instance_profile)
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"instance profile {instance_profile} never became readable via IAM within 60s"
                    )
                time.sleep(3)
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("account/region has no available Elastic Beanstalk solution stacks")
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_environment_status(ctx: Any, env_name: str, want_status: str, timeout_s: float = 900.0) -> None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if envs:
            last_status = envs[0]["Status"]
            if last_status == want_status:
                return
            if last_status in ("Terminated", "Terminating") and want_status != last_status:
                raise AssertionError(f"environment {env_name} unexpectedly reached {last_status}")
        time.sleep(2)
    raise AssertionError(f"environment {env_name} never reached status {want_status!r}, last seen {last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
