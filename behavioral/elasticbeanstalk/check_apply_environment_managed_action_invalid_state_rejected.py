"""apply-environment-managed-action-invalid-state-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "apply-environment-managed-action-invalid-state-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplyEnvironmentManagedAction gates on the environment's own state before it resolves
    ActionId: the same bogus ActionId is rejected with ElasticBeanstalkServiceException on a Ready
    environment and with InvalidParameterValue once the environment is Terminated."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-beh-app-")
    env_name = ctx.unique_name("sim2real-env-")[:40]
    action_id = str(uuid.uuid4())

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=_env_option_settings(ctx),
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, {"Ready"}, timeout_s=900, interval_s=15)

    # Positive control: on the live/Ready environment, the SAME bogus ActionId is rejected for
    # being an unknown action -- not for the environment being unavailable -- proving the target
    # reaches action-id resolution rather than blanket-rejecting every apply call.
    ready_code, ready_message = _error_code_and_message(
        lambda: eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    )
    assert ready_code == "ElasticBeanstalkServiceException", f"{ready_code}: {ready_message}"
    assert ready_message == "Managed update data not found for this environment.", ready_message

    eb.terminate_environment(EnvironmentName=env_name)
    terminated_env = _wait_env_status(eb, env_name, {"Terminated"}, timeout_s=600, interval_s=15, include_deleted=True)
    assert terminated_env["Status"] == "Terminated", terminated_env

    # Negative: the IDENTICAL ActionId on the now-Terminated environment is rejected for the
    # environment's state -- a different, specific code than the Ready-environment rejection
    # above, proving the environment-availability gate (not the action-id lookup) is what changed.
    code, message = _error_code_and_message(
        lambda: eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    )
    assert code == "InvalidParameterValue", f"{code}: {message}"
    assert message == f"No Environment found for EnvironmentName = '{env_name}'.", message
    assert code != ready_code, f"expected a different rejection once the environment is unavailable, got {code!r} both times"

    # Effect absent: the rejected call did not resurrect or otherwise alter the terminated
    # environment's own state.
    after = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"][0]
    assert after["Status"] == "Terminated", after


# ===== helpers =====

def _error_code_and_message(fn):
    """Return the (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Windows" not in s:
            return s
    return stacks[0]


def _ensure_env_iam(ctx):
    """Create-or-adopt the instance profile + service role an EB environment needs to launch
    ("Environment must have instance profile associated with it" otherwise -- a fresh sandbox
    account has no default one, unlike an account that has used the EB console). Registers LIFO
    teardown. Returns (instance_profile|None, service_role|None); degrades to (None, None) when
    IAM is unreachable, letting the service apply its (nonexistent, in a fresh account) default."""
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
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        }
        try:
            iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
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

    ec2_role = ctx.unique_name("sim2real-beh-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-beh-eb-service-role-")
    profile = ctx.unique_name("sim2real-beh-eb-ec2-profile-")
    ec2_ok = _create_role(ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"])
    service_role = (
        svc_role
        if _create_role(
            svc_role,
            "elasticbeanstalk.amazonaws.com",
            ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"],
        )
        else None
    )
    instance_profile = None
    if ec2_ok:
        made = True
        try:
            iam.create_instance_profile(InstanceProfileName=profile, Tags=[{"Key": "sim2real", "Value": "true"}])
            ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
        except Exception as exc:
            if "EntityAlreadyExists" not in str(exc):
                made = False
        if made:
            try:
                iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                ctx.on_cleanup(
                    lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                )
            except Exception:
                pass
            instance_profile = profile
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _env_option_settings(ctx) -> list[dict]:
    instance_profile, service_role = _ensure_env_iam(ctx)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:03:00"},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
    ]
    if instance_profile:
        settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )
    return settings


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=15.0, include_deleted=False):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=include_deleted)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return last
        time.sleep(interval_s)
    events = eb.describe_events(EnvironmentName=env_name, MaxRecords=10).get("Events", [])
    event_summary = "; ".join(f"{e.get('Severity')}: {e.get('Message')}" for e in events)
    raise AssertionError(
        f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r}); "
        f"recent events: {event_summary or '<none>'}"
    )


def _terminate_and_wait(eb, env_name):
    from botocore.exceptions import ClientError
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # InvalidParameterValue is "No Environment found": already terminated; anything else raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_env_status(eb, env_name, {"Terminated"}, timeout_s=600, interval_s=2, include_deleted=True)


def _delete_application(eb, app_name):
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=False)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
