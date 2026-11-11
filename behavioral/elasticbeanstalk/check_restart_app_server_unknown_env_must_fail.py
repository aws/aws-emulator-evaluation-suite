"""restart-app-server-unknown-env-must-fail."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restart-app-server-unknown-env-must-fail"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestartAppServer rejects a never-created environment name with InvalidParameterValue,
    while the same call on a Ready environment cycles it through Updating and advances
    DateUpdated, so a target that rejects every call cannot pass."""
    eb = ctx.client("elasticbeanstalk")

    # Negative: an environment name that was never created.
    bogus_env_name = ctx.unique_name("sim2real-eb-ghost-")
    code, message = _error_code(lambda: eb.restart_app_server(EnvironmentName=bogus_env_name))
    assert code == "InvalidParameterValue", (
        f"RestartAppServer on an unknown environment must fail with InvalidParameterValue, "
        f"got {code!r}"
    )
    expected = f"No Environment found for EnvironmentName = '{bogus_env_name}'."
    assert message == expected, (
        f"expected the refusal message {expected!r}, got {message!r}"
    )

    # Effect absent: the bogus name never corresponds to a real environment record.
    ghost = eb.describe_environments(EnvironmentNames=[bogus_env_name], IncludeDeleted=False)[
        "Environments"
    ]
    assert ghost == [], f"unexpected environment materialized for a bogus name: {ghost}"

    # Positive control: the identical call against a real, Ready environment performs a
    # real server-side restart rather than merely being accepted.
    app_name = _create_app(ctx)
    env_name = _create_ready_environment(ctx, app_name)

    before = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    date_updated_before = before["DateUpdated"]

    eb.restart_app_server(EnvironmentName=env_name)  # must not raise

    saw_updating = _poll_until_seen(ctx, env_name, {"Updating"}, timeout_s=180.0)
    assert saw_updating, (
        "RestartAppServer on a real Ready environment never put it into Updating -- looks like "
        "a no-op that only accepts the call"
    )

    # Terminal read: the environment settles Ready with a DateUpdated past the pre-restart one.
    deadline = time.monotonic() + 900.0
    while True:
        after = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
        if after["Status"] == "Ready" and after["DateUpdated"] > date_updated_before:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after RestartAppServer, {env_name} must settle Ready with an advanced "
                f"DateUpdated within 900s; last record {after!r}")
        time.sleep(2)
    assert after["Status"] == "Ready", after["Status"]
    assert after["DateUpdated"] > date_updated_before, (
        "DateUpdated did not advance after RestartAppServer -- no real server-side effect occurred"
    )

    # The earlier rejected call on the bogus name left this real environment untouched.
    assert after["EnvironmentName"] == env_name


# ===== helpers =====
_EB_PREFIX = "sim2real-eb-"


def _error_code(fn):
    """Call fn() expecting a ClientError; return its (Error.Code, Error.Message).

    Raises AssertionError when the call succeeds, so a missing refusal can never be read as a code.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _eb_name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_EB_PREFIX}{kind}-")


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    python_stacks = [s for s in stacks if "Python" in s and "Amazon Linux 2" in s and "Docker" not in s]
    candidates = python_stacks or [s for s in stacks if "Python" in s] or stacks
    return candidates[-1]


def _create_app(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    app_name = _eb_name(ctx, "app")
    eb.create_application(
        ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    return app_name


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "ec2role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    tags = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tags)
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=tags)
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


def _create_eb_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "svcrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    tags = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tags)["Role"]
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


def _create_env_with_retry(eb: Any, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    last_err = None
    for _ in range(attempts):
        try:
            eb.create_environment(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "InsufficientPrivilegesException":
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _wait_for_env_status(
    ctx: Any, env_name: str, target_statuses: set[str], timeout_s: float = 900.0, interval_s: float = 15.0
) -> str:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {target_statuses} within {timeout_s}s (last={last_status})")


def _poll_until_seen(ctx: Any, env_name: str, statuses: set[str], timeout_s: float = 180.0, interval_s: float = 5.0) -> bool:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name]).get("Environments", [])
        if envs and envs[0]["Status"] in statuses:
            return True
        time.sleep(interval_s)
    return False


def _terminate_environment(ctx: Any, env_name: str) -> None:
    eb = ctx.client("elasticbeanstalk")
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "InvalidParameterValue" and "No Environment found" in error.get("Message", ""):
            return
        raise
    _wait_for_env_status(ctx, env_name, {"Terminated"}, timeout_s=600.0, interval_s=2.0)


def _create_ready_environment(ctx: Any, app_name: str) -> str:
    eb = ctx.client("elasticbeanstalk")
    env_name = _eb_name(ctx, "env")
    stack = _pick_solution_stack(ctx)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
    ]
    kwargs = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "SolutionStackName": stack,
        "OptionSettings": option_settings,
        "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    }
    _create_env_with_retry(eb, kwargs)
    ctx.on_cleanup(lambda: _terminate_environment(ctx, env_name))
    _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0, interval_s=15.0)
    return env_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
