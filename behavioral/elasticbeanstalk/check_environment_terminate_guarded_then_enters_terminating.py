"""environment-terminate-guarded-then-enters-terminating."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-terminate-guarded-then-enters-terminating"
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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_env(eb, env_name):
    """DescribeEnvironments for one name (IncludeDeleted); return the record or None."""
    envs = eb.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=True
    ).get("Environments") or []
    return envs[0] if envs else None


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


def _wait_for_iam_visible(iam, *, role_names=(), profile_name=None, timeout_s=30.0, interval_s=3.0):
    """IAM is eventually consistent; poll GetRole/GetInstanceProfile until the principals this
    check just created are visible, bounding the wait EB itself needs before it can see them."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            for name in role_names:
                iam.get_role(RoleName=name)
            if profile_name:
                iam.get_instance_profile(InstanceProfileName=profile_name)
            return
        except Exception:
            time.sleep(interval_s)
    raise AssertionError(
        f"IAM principals never became visible: roles={list(role_names)!r} profile={profile_name!r}"
    )


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment needs, with LIFO
    teardown, memoized on ctx. Returns (instance_profile|None, service_role|None); (None, None)
    when IAM is unreachable, letting the service apply its defaults."""
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
    _wait_for_iam_visible(
        iam,
        role_names=[r for r in (ec2_role if ec2_ok else None, service_role) if r],
        profile_name=instance_profile,
    )
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
    kwargs.setdefault("Tags", [{"Key": "sim2real", "Value": "true"}])
    resp = eb.create_environment(ApplicationName=app_name, EnvironmentName=env_name, **kwargs)
    def _cleanup():
        envs = eb.describe_environments(
            EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments") or []
        if envs and envs[0].get("Status") not in ("Terminated", "Terminating"):
            eb.terminate_environment(EnvironmentName=env_name)

    ctx.on_cleanup(_cleanup)
    return resp


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateEnvironment is refused with InvalidParameterValue naming the initial or pending
    creation launch phase, then accepted once that phase clears, moving it to Terminated."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    resp = _launch_environment(ctx, eb, app_name)
    env_name = resp["EnvironmentName"]
    env_id = resp["EnvironmentId"]

    # 1) Immediately after creation the environment is not terminable.
    # message varies: it names the launch's internal sub-phase at the instant of the call
    # ("It is currently initial." or "It is currently pending creation."), so either exact
    # message is graded.
    code, message = _err(
        lambda: eb.terminate_environment(EnvironmentName=env_name)
    )
    assert code == "InvalidParameterValue", (
        f"terminating an environment still in its initial launch phase must be rejected "
        f"with InvalidParameterValue, got {code!r}"
    )
    phase = "pending creation" if message.endswith("pending creation.") else "initial"
    assert message == f"Cannot terminate environment named {resp['EnvironmentName']}. It is currently {phase}.", (
        f"expected the exact InvalidParameterValue message AWS returns, got {message!r}"
    )

    # 2) Once the initial phase clears, termination is accepted.
    state = {"resp": None}

    def try_terminate():
        try:
            state["resp"] = eb.terminate_environment(EnvironmentName=env_name)
            return True
        except Exception:
            return False

    _poll_until(try_terminate, lambda ok: ok is True, timeout_s=900, interval_s=15)
    term_resp = state["resp"]
    assert term_resp is not None
    assert term_resp["Status"] == "Terminating", (
        f"TerminateEnvironment must report Terminating, got {term_resp['Status']!r}"
    )
    assert term_resp["EnvironmentId"] == env_id
    assert term_resp["Health"] == "Grey"

    # The Terminating environment is still visible (it is not deleted yet).
    first = _describe_env(eb, env_name)
    assert first is not None
    assert first["Status"] in ("Terminating", "Terminated"), first["Status"]

    # The terminated environment stays visible under IncludeDeleted.
    described = _poll_until(
        lambda: _describe_env(eb, env_name),
        lambda env: env is None or env.get("Status") != "Terminating",
        timeout_s=900, interval_s=15,
        description="the terminating environment leaving Terminating",
    )
    assert described is not None, f"{env_name} must stay visible under IncludeDeleted"
    assert described["Status"] == "Terminated", (
        f"the environment must settle Terminated, got {described['Status']!r}"
    )
    assert described["AbortableOperationInProgress"] is False, (
        "a termination in progress must not be reported as an abortable update"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
