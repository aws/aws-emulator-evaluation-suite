"""update-environment-tier-change-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-environment-tier-change-rejected"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironment that changes an environment's Tier fails with InvalidParameterValue and the exact message
    and leaves Tier WebServer/Standard, while a Description-only update on the same environment applies."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-tier-")
    env_name = ctx.unique_name("sim2real-tier-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        Tier={"Name": "WebServer", "Type": "Standard"},
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        ],
    )
    before = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900)
    assert before["Tier"]["Name"] == "WebServer", f"expected freshly-created env Tier.Name 'WebServer', got {before['Tier']!r}"

    # Positive control: a harmless, non-tier update succeeds.
    unique_desc = ctx.unique_name("sim2real-desc-")
    eb.update_environment(EnvironmentName=env_name, Description=unique_desc)
    updated = _wait_for_description(eb, env_name, unique_desc, timeout_s=120)
    assert updated["Description"] == unique_desc, f"expected Description {unique_desc!r} after non-tier update, got {updated.get('Description')!r}"

    # Negative: changing the tier is rejected.
    def _change_tier():
        eb.update_environment(
            EnvironmentName=env_name, Tier={"Name": "Worker", "Type": "SQS/HTTP", "Version": "1.0"}
        )

    code, message = _error_code(_change_tier)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue rejecting a tier change, got {code!r}"
    expected_message = f"Unsupported environment tier Worker version 1.0 for solution stack '{stack}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the tier on the environment is unchanged.
    after = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
    assert after["Tier"]["Name"] == "WebServer", f"expected Tier.Name still 'WebServer' after rejected change, got {after['Tier']!r}"
    assert after["Tier"]["Type"] == "Standard", f"expected Tier.Type still 'Standard' after rejected change, got {after['Tier']!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    a target ACCEPTING a tier change real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("real AWS rejects a tier change on an existing environment, but it SUCCEEDED")


def _create_eb_instance_profile(ctx) -> str:
    """A fresh account has no ambient ``aws-elasticbeanstalk-ec2-role`` -- without one,
    the ASG's launch config has no instance profile and instances never launch, leaving the
    environment stuck in Launching with a DateUpdated that never advances."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)

    def _cleanup() -> None:
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_instance_profile(InstanceProfileName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name


def _create_eb_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup() -> None:
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_env_status(eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses}; last={last}")


def _wait_for_description(eb, env_name: str, expected: str, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last.get("Description") == expected:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} description never became {expected!r}; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
