"""delete-environment-configuration-removes-saved-config."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-environment-configuration-removes-saved-config"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


_NS_LAUNCHCONFIG = "aws:autoscaling:launchconfiguration"
_ORIGINAL_INSTANCE_TYPE = "t3.micro"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEnvironmentConfiguration on a running environment with no pending draft is accepted and
    leaves the one deployed configuration set intact (same count, still deployed, same InstanceType):
    a target that rejects it for lacking a draft, or drops the deployed set, diverges."""
    eb = ctx.client("elasticbeanstalk")
    tag = [{"Key": "sim2real", "Value": "eb-delete-env-config-removes-saved-config"}]
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    svc_role_name, ec2_profile_name = _create_eb_roles(ctx)
    stack = _pick_solution_stack(eb)
    _create_environment_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": _NS_LAUNCHCONFIG, "OptionName": "InstanceType", "Value": _ORIGINAL_INSTANCE_TYPE},
            {"Namespace": _NS_LAUNCHCONFIG, "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
        ],
        Tags=tag,
    )
    ctx.on_cleanup(lambda: _safe(lambda: eb.terminate_environment(EnvironmentName=env_name, TerminateResources=True)))
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900.0)

    baseline = eb.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)[
        "ConfigurationSettings"
    ]
    assert len(baseline) == 1, f"expected exactly one (deployed) configuration set before any update, got {baseline!r}"
    assert baseline[0].get("DeploymentStatus") == "deployed", (
        f"expected the sole pre-update configuration set to be deployed, got {baseline[0].get('DeploymentStatus')!r}"
    )
    assert _option_value(baseline[0], _NS_LAUNCHCONFIG, "InstanceType") == _ORIGINAL_INSTANCE_TYPE, (
        f"expected the deployed configuration to carry InstanceType={_ORIGINAL_INSTANCE_TYPE!r}, "
        f"got {_option_value(baseline[0], _NS_LAUNCHCONFIG, 'InstanceType')!r}"
    )

    # The operation under test, on an environment with no pending draft. It must be ACCEPTED: any
    # ClientError here is the finding, so it is deliberately not swallowed.
    eb.delete_environment_configuration(ApplicationName=app_name, EnvironmentName=env_name)

    after, observed_counts = _poll_configuration_settings(eb, app_name, env_name, expected_count=1, timeout_s=60.0)
    if after is None:
        raise AssertionError(
            "DescribeConfigurationSettings no longer returns exactly one configuration set after "
            "DeleteEnvironmentConfiguration on a draft-less environment; counts observed over the "
            f"poll window: {observed_counts!r}"
        )
    assert after[0].get("DeploymentStatus") == "deployed", (
        f"expected the surviving configuration set to still be deployed, got "
        f"{after[0].get('DeploymentStatus')!r}"
    )
    assert _option_value(after[0], _NS_LAUNCHCONFIG, "InstanceType") == _ORIGINAL_INSTANCE_TYPE, (
        "DeleteEnvironmentConfiguration must not disturb the deployed configuration when there is "
        f"no draft to delete; InstanceType is now "
        f"{_option_value(after[0], _NS_LAUNCHCONFIG, 'InstanceType')!r}, expected "
        f"{_ORIGINAL_INSTANCE_TYPE!r}"
    )


# ===== helpers =====


def _safe(fn) -> None:
    """Run one teardown call; only a not-found answer means already gone, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "NoSuchEntity" or (err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", ""))):
            raise


def _option_value(config: dict, namespace: str, name: str) -> str | None:
    for opt in config.get("OptionSettings", []):
        if opt.get("Namespace") == namespace and opt.get("OptionName") == name:
            return opt.get("Value")
    return None


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


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _wait_for_env_status(eb, env_name: str, statuses: set, timeout_s: float, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"environment {env_name} did not reach {statuses} within {timeout_s}s "
        f"(last status={last['Status'] if last else None})"
    )


def _poll_configuration_settings(
    eb, app_name: str, env_name: str, expected_count: int, timeout_s: float, interval_s: float = 5.0
) -> tuple[list | None, list[int]]:
    """Poll until ConfigurationSettings has exactly expected_count entries. Returns
    (settings, observed_counts) on success, or (None, observed_counts) on timeout --
    observed_counts is the de-duplicated sequence of counts seen, for diagnosing a
    hypothesis about the transition (e.g. "never left 1", "briefly hit 3") on failure.
    """
    deadline = time.monotonic() + timeout_s
    observed_counts: list[int] = []
    while time.monotonic() < deadline:
        settings = eb.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)[
            "ConfigurationSettings"
        ]
        if not observed_counts or observed_counts[-1] != len(settings):
            observed_counts.append(len(settings))
        if len(settings) == expected_count:
            return settings, observed_counts
        time.sleep(interval_s)
    return None, observed_counts


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
