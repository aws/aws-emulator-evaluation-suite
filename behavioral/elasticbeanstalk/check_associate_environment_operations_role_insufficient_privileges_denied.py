"""associate-environment-operations-role-insufficient-privileges-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-environment-operations-role-insufficient-privileges-denied"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole fails with InsufficientPrivilegesException for a caller
    lacking iam:PassRole on the role; a caller with PassRole succeeds and the association shows."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    app_name = ctx.unique_name("sim2real-beh-app-")
    env_name = ctx.unique_name("sim2real-env-")[:40]
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    stack = _pick_solution_stack(eb)
    instance_profile = _create_eb_instance_profile(ctx, iam)
    service_role_arn = _create_eb_service_role(ctx, iam, account_id)
    # Before the environment, so its teardown runs AFTER the environment's (LIFO): Beanstalk
    # assumes the operations role to terminate, and deleting it first leaves the env unterminatable.
    ops_role_arn = _create_ops_role(ctx, iam, account_id)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, {"Ready"}, timeout_s=900, interval_s=15)

    restricted_role_arn = _create_restricted_role(
        ctx, iam, account_id,
        allow_actions=["elasticbeanstalk:*"],
        deny_actions=["iam:PassRole"],
    )
    restricted_eb = _assume_role_client(ctx, sts, "elasticbeanstalk", restricted_role_arn)
    _wait_for_active(lambda: restricted_eb.describe_applications())

    code, message = _error_code(
        lambda: restricted_eb.associate_environment_operations_role(
            EnvironmentName=env_name, OperationsRole=ops_role_arn
        )
    )
    assert code == "InsufficientPrivilegesException", (
        f"expected InsufficientPrivilegesException for a caller lacking iam:PassRole, got {code!r}"
    )
    expected = "Insufficient privileges for IAM PassRole Action."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the environment must still have no operations role.
    env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert env.get("OperationsRole") is None, (
        f"expected no OperationsRole after the rejected call, got {env.get('OperationsRole')!r}"
    )

    # Positive control: a caller with iam:PassRole for the role succeeds.
    eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=ops_role_arn)
    env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert env.get("OperationsRole") == ops_role_arn, (
        f"expected OperationsRole={ops_role_arn!r} after the properly-privileged call, "
        f"got {env.get('OperationsRole')!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected success raises, so a
    target accepting a call real AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Windows" not in s:
            return s
    return stacks[0]


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=15.0, include_deleted=True):
    # IncludeDeleted=True by default: a Terminated environment is otherwise invisible to
    # DescribeEnvironments, so a fast failure would silently burn the full timeout and get
    # reported as "never appeared" instead of naming the terminal status and its error events.
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=include_deleted)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None:
            if last["Status"] in statuses:
                return last
            if last["Status"] == "Terminated" and "Terminated" not in statuses:
                events = eb.describe_events(EnvironmentName=env_name, Severity="ERROR", MaxRecords=10).get(
                    "Events", []
                )
                raise AssertionError(
                    f"environment {env_name} reached Terminated (never {statuses}); "
                    f"error events={[e.get('Message') for e in events]!r}"
                )
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r})")


def _terminate_and_wait(eb, env_name, timeout_s=600.0, interval_s=2.0):
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
            except ClientError as exc:
                # An in-flight update answers InvalidParameterValue ("invalid state"): retry it; raise the rest.
                if exc.response["Error"]["Code"] not in ("InvalidParameterValue", "OperationInProgressFailure"):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s}s")


def _delete_application(eb, app_name):
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=False)


def _create_eb_instance_profile(ctx, iam) -> str:
    """EB refuses to launch an environment with no EC2 instance profile (``Environment must have
    instance profile associated with it.``), and a freshly provisioned account has no ambient
    ``aws-elasticbeanstalk-ec2-role`` to fall back on -- so this creates its own."""
    role_name = ctx.unique_name("sim2real-ebec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _delete_instance_profile(iam, role_name, policy_arn))
    return role_name


def _delete_instance_profile(iam, role_name, policy_arn):
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


def _create_eb_service_role(ctx, iam, account_id) -> str:
    role_name = ctx.unique_name("sim2real-ebsvc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "elasticbeanstalk.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    ctx.on_cleanup(lambda: _delete_service_role(iam, role_name, policy_arns))
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _delete_service_role(iam, role_name, policy_arns):
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


def _create_ops_role(ctx, iam, account_id):
    role_name = ctx.unique_name("sim2real-ebops-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "elasticbeanstalk.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return f"arn:aws:iam::{account_id}:role/{role_name}"


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
