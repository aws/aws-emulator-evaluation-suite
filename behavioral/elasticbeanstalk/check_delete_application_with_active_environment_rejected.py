"""delete-application-with-active-environment-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-application-with-active-environment-rejected"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApplication of an application with a Ready environment fails with InvalidParameterValue and the exact
    message, leaves the application and its Ready environment in place, and succeeds with TerminateEnvByForce=true."""
    eb = ctx.client("elasticbeanstalk")

    # Positive control: plain DeleteApplication succeeds on an application with no
    # environment at all, ruling out "DeleteApplication always fails without the
    # force flag" as an alternative explanation for the rejection asserted below.
    control_app = ctx.unique_name("sim2real-eb-ctrl-")[:100]
    eb.create_application(ApplicationName=control_app, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: _safe_delete_application(ctx, control_app))
    eb.delete_application(ApplicationName=control_app)
    _wait_application_gone(ctx, control_app, timeout_s=60.0)

    app_name = ctx.unique_name("sim2real-eb-app-")[:100]
    env_name = ctx.unique_name("sim2real-eb-env-")[:40]

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    # Fallback cleanup in case the positive control below never runs; harmless no-op
    # once the app has already been deleted.
    ctx.on_cleanup(lambda: _safe_delete_application(ctx, app_name))

    stack = _pick_solution_stack(ctx)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=_env_option_settings(ctx),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    _wait_env_status(ctx, app_name, env_name, {"Ready"}, timeout_s=900.0)

    code, message = _error_code(lambda: eb.delete_application(ApplicationName=app_name))
    assert code == "InvalidParameterValue", (
        f"DeleteApplication without TerminateEnvByForce must be rejected with "
        f"InvalidParameterValue while a Ready environment exists; got {code!r}"
    )
    expected = (
        f"Unable to delete application {app_name} because it has a version that is deployed "
        "to a running environment."
    )
    assert message == expected, (
        f"DeleteApplication with a Ready environment must say {expected!r}, got {message!r}"
    )

    # Effect absent: the application and its environment are both still there.
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert len(apps) == 1, f"expected application {app_name} to still exist after the refused delete, found {len(apps)}"
    envs = eb.describe_environments(ApplicationName=app_name, EnvironmentNames=[env_name], IncludeDeleted=False)[
        "Environments"
    ]
    assert len(envs) == 1 and envs[0]["Status"] == "Ready", (
        f"expected environment {env_name} to remain Ready after the refused delete, found {envs}"
    )

    # Positive control: the same call succeeds once TerminateEnvByForce=true is set.
    # TerminateEnvByForce=True on a Ready environment triggers async environment
    # teardown (EC2/ASG/ELB) before the application itself is removed, on the same
    # order of wall time as CreateEnvironment.
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)
    _wait_application_gone(ctx, app_name, timeout_s=900.0)


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment
    needs to leave Launching, registering teardown. Returns (instance_profile|None,
    service_role|None); degrades to (None, None) when IAM is unreachable, letting the
    service apply its defaults. A fresh account has no default
    aws-elasticbeanstalk-ec2-role/instance profile (that is normally auto-created by
    the EB console on first use, not by the API), so without this the environment's
    EC2 instances never register and it never leaves Launching.
    """
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        return None, None

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        except Exception as exc:
            if "EntityAlreadyExists" not in str(exc):
                return False
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policy_arns:
            try:
                iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))
            except Exception:
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
        except Exception as exc:
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
            except Exception:
                pass
            instance_profile = profile
    # IAM is eventually consistent; poll its own read path, a lower bound on the
    # visibility EB's control plane needs.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            if instance_profile:
                iam.get_instance_profile(InstanceProfileName=instance_profile)
            if service_role:
                iam.get_role(RoleName=service_role)
            break
        except Exception:
            time.sleep(2.0)
    return instance_profile, service_role


def _env_option_settings(ctx) -> list[dict]:
    """Baseline option settings that make a single-instance environment actually launch."""
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


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Amazon Linux 2" in s and "Windows" not in s:
            return s
    if not stacks:
        raise AssertionError("no Elastic Beanstalk solution stacks available in this region/account")
    return stacks[0]


def _wait_env_status(ctx, app: str, env: str, terminal_statuses, timeout_s: float = 900.0, interval_s: float = 15.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(ApplicationName=app, EnvironmentNames=[env], IncludeDeleted=False)[
            "Environments"
        ]
        if envs:
            last = envs[0]["Status"]
            if last in terminal_statuses:
                return envs[0]
        time.sleep(interval_s)
    raise AssertionError(f"environment {env} never reached {terminal_statuses}; last status={last}")


def _wait_application_gone(ctx, app: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        apps = eb.describe_applications(ApplicationNames=[app])["Applications"]
        if not apps:
            return
        time.sleep(interval_s)
    raise AssertionError(f"application {app} was never removed after forced DeleteApplication")


def _safe_delete_application(ctx, app: str) -> None:
    eb = ctx.client("elasticbeanstalk")
    eb.delete_application(ApplicationName=app, TerminateEnvByForce=True)


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
