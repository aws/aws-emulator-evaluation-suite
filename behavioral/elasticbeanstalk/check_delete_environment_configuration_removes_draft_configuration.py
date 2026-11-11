"""delete-environment-configuration-removes-draft-configuration."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-environment-configuration-removes-draft-configuration"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]

_OPTION_NS = "aws:elasticbeanstalk:application:environment"
_OPTION_NAME = "SIM2REAL_MARKER"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An UpdateEnvironment option change converges into the environment's ONE deployed
    configuration set, and a following DeleteEnvironmentConfiguration on that draft-less
    environment is accepted and leaves the updated deployed set intact.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")[:100]
    env_name = ctx.unique_name("sim2real-eb-env-")[:40]
    template_name = ctx.unique_name("sim2real-eb-tmpl-")[:100]
    template_value = "template-value"
    updated_value = "updated-value"

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    svc_role_name, ec2_profile_name = _create_eb_roles(ctx)
    stack = _pick_solution_stack(ctx)
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
            {"Namespace": _OPTION_NS, "OptionName": _OPTION_NAME, "Value": template_value},
        ],
    )

    _create_environment_with_retry(
        ctx, eb, ApplicationName=app_name, EnvironmentName=env_name, TemplateName=template_name
    )
    ctx.on_cleanup(lambda: _safe(lambda: eb.terminate_environment(EnvironmentName=env_name, TerminateResources=True)))
    _wait_env_status(ctx, app_name, env_name, {"Ready"}, timeout_s=900.0)

    settings = eb.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)[
        "ConfigurationSettings"
    ]
    assert len(settings) == 1, f"expected exactly one (deployed) configuration set, got {settings!r}"
    assert settings[0].get("DeploymentStatus") == "deployed", settings[0].get("DeploymentStatus")
    assert _option_value(settings[0], _OPTION_NS, _OPTION_NAME) == template_value, (
        f"expected the template's option value {template_value!r}, got "
        f"{_option_value(settings[0], _OPTION_NS, _OPTION_NAME)!r}"
    )

    eb.update_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        OptionSettings=[{"Namespace": _OPTION_NS, "OptionName": _OPTION_NAME, "Value": updated_value}],
    )
    _wait_env_status(ctx, app_name, env_name, {"Ready"}, timeout_s=600.0)

    updated = _wait_for_single_deployed_value(ctx, app_name, env_name, updated_value, timeout_s=300.0)
    assert updated is not None, (
        f"the option change to {updated_value!r} never became the environment's single deployed "
        f"configuration set"
    )

    # The operation under test, on an environment with no pending draft. It must be ACCEPTED: any
    # ClientError here is the finding, so it is deliberately not swallowed.
    eb.delete_environment_configuration(ApplicationName=app_name, EnvironmentName=env_name)

    after = eb.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)[
        "ConfigurationSettings"
    ]
    assert len(after) == 1, (
        f"DeleteEnvironmentConfiguration on a draft-less environment must leave the single deployed "
        f"configuration set; got {after!r}"
    )
    assert after[0].get("DeploymentStatus") == "deployed", after[0].get("DeploymentStatus")
    assert _option_value(after[0], _OPTION_NS, _OPTION_NAME) == updated_value, (
        f"the surviving configuration must still carry the updated value {updated_value!r}, got "
        f"{_option_value(after[0], _OPTION_NS, _OPTION_NAME)!r}"
    )


# ===== helpers =====

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


def _wait_for_single_deployed_value(ctx, app: str, env: str, expected_value: str, timeout_s: float = 300.0):
    """Poll until DescribeConfigurationSettings reports exactly one deployed set carrying
    expected_value, or return None on timeout."""
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        settings = eb.describe_configuration_settings(ApplicationName=app, EnvironmentName=env)[
            "ConfigurationSettings"
        ]
        last = settings
        if (
            len(settings) == 1
            and settings[0].get("DeploymentStatus") == "deployed"
            and _option_value(settings[0], _OPTION_NS, _OPTION_NAME) == expected_value
        ):
            return settings[0]
        time.sleep(5.0)
    print(f"[diagnostic] last DescribeConfigurationSettings response: {last!r}")
    return None


def _safe(fn) -> None:
    """Run one teardown call; only a not-found answer means already gone, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "NoSuchEntity" or (err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", ""))):
            raise


def _create_eb_roles(ctx) -> tuple[str, str]:
    """Create the EB service role and EC2 instance profile explicitly.

    CreateEnvironment's implicit default-role auto-creation (aws-elasticbeanstalk-ec2-role /
    aws-elasticbeanstalk-service-role) is not reliable from a raw API call in a fresh
    account: without an instance profile the launched EC2 instance cannot pull the application
    version from S3, fails its health check, and Elastic Beanstalk terminates the environment.
    """
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-eb-role-")
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

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=svc_name)))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: _safe(lambda: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p)))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=ec2_name)))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")))

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)))

    return svc_name, ec2_name


def _create_environment_with_retry(ctx, eb, **kwargs) -> dict:
    """Retry on InsufficientPrivilegesException every 2 s for up to 80 s: IAM role/instance-profile
    creation is eventually consistent, so Elastic Beanstalk may not yet be able to assume the
    just-created ServiceRole or pass the just-created IamInstanceProfile."""
    left = ctx.time_left()
    deadline = time.monotonic() + (80.0 if left is None else max(1.0, min(80.0, left - 5.0)))
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _option_value(config_settings: dict, namespace: str, option_name: str):
    for opt in config_settings.get("OptionSettings", []):
        if opt.get("Namespace") == namespace and opt.get("OptionName") == option_name:
            return opt.get("Value")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
