"""environment-create-enters-launching."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "environment-create-enters-launching"
GROUP = 'environment-lifecycle'
SERVICES = ['elasticbeanstalk']

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


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment needs,
    registering LIFO teardown. Returns (instance_profile|None, service_role|None); degrades
    to (None, None) when IAM is unreachable (an emulator that does not serve IAM), letting the
    service apply its defaults. Memoized on ctx so an env-creating check provisions IAM once."""
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
    if instance_profile or service_role:
        def _iam_visible():
            ok = True
            if instance_profile:
                try:
                    iam.get_instance_profile(InstanceProfileName=instance_profile)
                except Exception:
                    ok = False
            if service_role:
                try:
                    iam.get_role(RoleName=service_role)
                except Exception:
                    ok = False
            return ok
        _poll_until(
            _iam_visible, lambda ok: ok, timeout_s=60, interval_s=2.0,
            description="IAM role/instance profile visible before CreateEnvironment",
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
        # By the time cleanup runs, wait_env_leaves_launching() (called before run() returns)
        # has already taken the environment out of Launching, so that wait does not
        # happen here. A stale describe is still fine: skip if it is already gone/terminating.
        current = _describe_env(eb, env_name)
        if current is not None and current.get("Status") not in ("Terminated", "Terminating"):
            eb.terminate_environment(EnvironmentName=env_name)

    ctx.on_cleanup(_cleanup)
    return resp


def _wait_env_leaves_launching(eb, env_name, *, timeout_s=900, interval_s=15.0):
    """Block, in the check body (which has budget for it), until the environment is no
    longer Launching. TerminateEnvironment is refused with InvalidParameterValue ("It is
    currently pending creation") while Launching, so the body waits for the launch to
    settle before teardown runs."""
    return _poll_until(
        lambda: _describe_env(eb, env_name),
        lambda env: env is None or env.get("Status") != "Launching",
        timeout_s=timeout_s, interval_s=interval_s,
        description="environment leaves Launching (required before teardown can terminate it)",
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment returns a launching environment with identity assigned, then settles Ready.

    The check asserts the derived attributes that exist as soon as the environment does, then
    polls the launch to its terminal state and grades that state.
    """
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    resp = _launch_environment(ctx, eb, app_name)
    env_name = resp["EnvironmentName"]
    assert resp["Status"] == "Launching", (
        f"a newly created environment must start in Launching, got {resp['Status']!r}"
    )
    assert resp["Health"] == "Grey", (
        f"a Launching environment must report Grey health, got {resp.get('Health')!r}"
    )
    env_id = resp["EnvironmentId"]
    assert env_id.startswith("e-"), f"EnvironmentId must be an e-* id, got {env_id!r}"
    assert resp["EnvironmentArn"].endswith(f"{app_name}/{env_name}"), (
        f"EnvironmentArn must embed application/environment, got {resp['EnvironmentArn']!r}"
    )
    assert "CNAME" not in resp, (
        "CreateEnvironment must not report a CNAME before the environment is provisioned"
    )
    assert resp["ApplicationName"] == app_name, (
        f"CreateEnvironment must echo the ApplicationName it was given, "
        f"expected {app_name!r}, got {resp.get('ApplicationName')!r}"
    )
    assert resp["SolutionStackName"] == _solution_stack(eb), (
        f"expected the requested SolutionStackName {_solution_stack(eb)!r}, "
        f"got {resp.get('SolutionStackName')!r}"
    )
    assert resp["Tier"]["Name"] == "WebServer", "default tier must be WebServer"

    # DescribeEnvironments must agree with the create response.
    described = _describe_env(eb, env_name)
    assert described is not None, (
        f"DescribeEnvironments must find the just-created environment {env_name!r}, got no record"
    )
    assert described["EnvironmentId"] == env_id, (
        f"expected DescribeEnvironments to report EnvironmentId {env_id!r}, "
        f"got {described.get('EnvironmentId')!r}"
    )
    assert described["Status"] in ("Launching", "Ready"), (
        f"expected Status in ('Launching', 'Ready'), got {described.get('Status')!r}"
    )
    assert described["AbortableOperationInProgress"] is False, (
        "an initial environment launch is not an abortable update"
    )

    # The option settings supplied at creation are readable from the live environment.
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, EnvironmentName=env_name
    )["ConfigurationSettings"][0]
    assert settings["EnvironmentName"] == env_name, (
        f"DescribeConfigurationSettings must scope to {env_name!r}, "
        f"got {settings.get('EnvironmentName')!r}"
    )
    env_type = [
        o
        for o in settings["OptionSettings"]
        if o["Namespace"] == "aws:elasticbeanstalk:environment"
        and o["OptionName"] == "EnvironmentType"
    ]
    assert env_type and env_type[0]["Value"] == "SingleInstance", (
        "the EnvironmentType requested at creation must be reflected in the settings"
    )

    # Resource view exists as soon as the environment does.
    resources = eb.describe_environment_resources(EnvironmentName=env_name)[
        "EnvironmentResources"
    ]
    assert resources["EnvironmentName"] == env_name, (
        f"DescribeEnvironmentResources must scope to {env_name!r}, "
        f"got {resources.get('EnvironmentName')!r}"
    )
    for key in ("Instances", "AutoScalingGroups", "LaunchConfigurations", "LoadBalancers"):
        assert key in resources, f"EnvironmentResources must include {key}"

    # Launching an environment emits events scoped to that environment.
    def probe():
        return eb.describe_events(EnvironmentName=env_name)["Events"]

    _poll_until(
        probe, lambda evs: len(evs) > 0, timeout_s=120, interval_s=10,
        description="environment emits at least one scoped event",
    )
    events = probe()
    assert events, "creating an environment must emit environment events"
    assert all(e["EnvironmentName"] == env_name for e in events), (
        f"every event from DescribeEvents(EnvironmentName={env_name!r}) must be scoped to it, "
        f"got names {sorted({e.get('EnvironmentName') for e in events})!r}"
    )

    # The launch settles: the terminal state is Ready, which also lets teardown's
    # TerminateEnvironment through (see _wait_env_leaves_launching's docstring).
    final = _wait_env_leaves_launching(eb, env_name, timeout_s=1200)
    assert final is not None, f"{env_name} must stay visible after its launch settles"
    assert final["Status"] == "Ready", (
        f"a launched environment must settle Ready, got {final['Status']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
