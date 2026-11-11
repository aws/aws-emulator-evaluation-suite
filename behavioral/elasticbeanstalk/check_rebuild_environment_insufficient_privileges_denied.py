"""rebuild-environment-insufficient-privileges-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rebuild-environment-insufficient-privileges-denied"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebuildEnvironment by a caller with elasticbeanstalk:* but no EC2/AutoScaling/ELB rights fails
    with InvalidParameterValue wrapping EC2 UnauthorizedOperation and leaves the environment Ready;
    a privileged caller then rebuilds it onto a new instance."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    app_name = ctx.unique_name("sim2real-beh-app-")
    env_name = ctx.unique_name("sim2real-env-")[:40]
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    svc_role_name, ec2_profile_name = _create_eb_roles(ctx, iam)

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, {"Ready"}, timeout_s=900, interval_s=2)

    restricted_role_arn = _create_restricted_role(
        ctx, iam, account_id,
        allow_actions=["elasticbeanstalk:*"],
        deny_actions=["ec2:*", "autoscaling:*", "elasticloadbalancing:*", "cloudformation:*"],
    )
    restricted_eb = _assume_role_client(ctx, sts, "elasticbeanstalk", restricted_role_arn)
    _wait_for_active(lambda: restricted_eb.describe_applications())

    code, message = _error_code_and_message(lambda: restricted_eb.rebuild_environment(EnvironmentName=env_name))
    # EB surfaces the downstream EC2 denial, not InsufficientPrivilegesException.
    # message varies: it embeds the per-request EC2 encoded authorization failure message, so
    # the stable parts that name the denial are graded.
    assert code == "InvalidParameterValue", f"{code}: {message}"
    assert message and "not authorized to perform" in message and "UnauthorizedOperation" in message, message
    # The denied ec2 action and the encoded failure are server-chosen, so the stable prefix is exact.
    role_name = restricted_role_arn.rsplit("/", 1)[-1]
    assert message.startswith(
        "You are not authorized to perform this operation. User: "
        f"arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav is not authorized to perform: ec2:"
    ), message
    # The EC2 error trailer ends in a request id, then a fixed suffix.
    assert message.endswith("; Proxy: null)"), message

    # Effect absent: the environment must remain Ready, no tear-down/rebuild started.
    env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert env["Status"] == "Ready"

    # Positive control: a fully-privileged rebuild moves off Ready ("Updating": the record is updated
    # in place) and settles Ready again on a replacement instance.
    def _instances():
        res = eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]
        return {i["Id"] for i in res["Instances"]}

    before = _instances()
    assert before, f"a Ready SingleInstance environment must report its instance, got {before!r}"
    eb.rebuild_environment(EnvironmentName=env_name)
    left_status = _wait_env_left_status(eb, env_name, "Ready", timeout_s=120, interval_s=5)
    assert left_status != "Ready", left_status
    deadline = time.monotonic() + 1200
    while True:
        status = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]["Status"]
        after = _instances() if status == "Ready" else set()
        if status == "Ready" and after and after.isdisjoint(before):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after RebuildEnvironment, {env_name} must settle Ready on a new instance within "
                f"1200s; last Status {status!r}, instances {after!r}, before {before!r}")
        time.sleep(2)


def _error_code_and_message(fn):
    """Call fn() expecting a ClientError; return its (Error.Code, Error.Message).

    Raises AssertionError when the call succeeds, so a missing refusal can never be read as a code.
    """
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Windows" not in s:
            return s
    return stacks[0]


def _create_eb_roles(ctx, iam):
    """CreateEnvironment without ServiceRole/IamInstanceProfile falls back to the console-created
    aws-elasticbeanstalk-* roles and fails fast if they are absent, so create our own."""
    svc_name = ctx.unique_name("sim2real-eb-svcrole-")
    ec2_name = ctx.unique_name("sim2real-eb-ec2role-")
    svc_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    ec2_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust)
    ctx.on_cleanup(lambda: _delete_role(iam, svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: _delete_role(iam, ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: _delete_instance_profile(iam, ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)

    _wait_iam_ready(iam, svc_name, ec2_name)
    return svc_name, ec2_name


def _wait_iam_ready(iam, svc_name, ec2_name, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=svc_name)
            profile = iam.get_instance_profile(InstanceProfileName=ec2_name)["InstanceProfile"]
            if any(r["RoleName"] == ec2_name for r in profile.get("Roles", [])):
                return
        except Exception as e:
            last_err = e
        time.sleep(interval_s)
    raise AssertionError(
        f"IAM role/instance-profile for Elastic Beanstalk never became visible within {timeout_s}s: {last_err}"
    )


def _delete_instance_profile(iam, profile_name):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_env_left_status(eb, env_name, from_status, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None and last["Status"] != from_status:
            return last["Status"]
        time.sleep(interval_s)
    raise AssertionError(
        f"environment {env_name} never left status {from_status!r} within {timeout_s}s (last={last!r})"
    )


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return last
        if last is not None and last["Status"] == "Terminated" and "Terminated" not in statuses:
            raise AssertionError(
                f"environment {env_name} terminated while waiting for {statuses} "
                f"(health={last.get('Health')!r}, health_status={last.get('HealthStatus')!r})"
            )
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r})")


def _terminate_and_wait(eb, env_name):
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the wanted state; anything else re-raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_env_status(eb, env_name, {"Terminated"}, timeout_s=600, interval_s=2)


def _delete_application(eb, app_name):
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=False)


def _create_restricted_role(ctx, iam, account_id, allow_actions, deny_actions):
    role_name = ctx.unique_name("sim2real-ebrestrict-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": allow_actions, "Resource": "*"},
            {"Effect": "Deny", "Action": deny_actions, "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted", PolicyDocument=json.dumps(policy_doc))
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_client(ctx, sts, service_name, role_arn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
            return ctx.client(
                service_name,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume restricted role {role_arn}: {last_err}")


def _wait_for_active(probe, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            probe()
            return
        except Exception as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"restricted role's attached policy never became active: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
