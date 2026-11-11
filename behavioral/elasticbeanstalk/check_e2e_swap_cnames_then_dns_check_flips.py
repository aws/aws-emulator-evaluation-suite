"""e2e-swap-cnames-then-dns-check-flips."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-swap-cnames-then-dns-check-flips"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create two environments, swap their CNAMEs, and confirm DescribeEnvironments shows each
    environment now answering under the other's former CNAME, with CheckDNSAvailability
    reporting the swapped prefix as still in use (now by the other environment)."""
    eb = ctx.client("elasticbeanstalk")
    tag = [{"Key": "sim2real", "Value": CHECK}]
    app_name = ctx.unique_name("sim2real-ebswap-app-")
    env1_name = _short_env_name(ctx, "ebsw1")
    env2_name = _short_env_name(ctx, "ebsw2")
    prefix1 = _short_env_name(ctx, "ebswc1").lower()
    prefix2 = _short_env_name(ctx, "ebswc2").lower()

    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(ctx)
    instance_profile, service_role = _ensure_env_iam(ctx)
    opts = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    if instance_profile:
        opts.append({"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile})
    if service_role:
        opts.append({"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role})
        opts.append({"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"})
    _create_env_retrying_iam_propagation(
        eb, ApplicationName=app_name, EnvironmentName=env1_name, SolutionStackName=stack,
        CNAMEPrefix=prefix1, OptionSettings=opts, Tags=tag,
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env1_name))
    _create_env_retrying_iam_propagation(
        eb, ApplicationName=app_name, EnvironmentName=env2_name, SolutionStackName=stack,
        CNAMEPrefix=prefix2, OptionSettings=opts, Tags=tag,
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env2_name))

    env1 = _wait_env_status(ctx, env1_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    env2 = _wait_env_status(ctx, env2_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env1["Status"] == "Ready" and env2["Status"] == "Ready", (
        f"both environments must reach Ready before the swap; got {env1['Status']!r} and {env2['Status']!r}"
    )

    cname1_before, cname2_before = env1["CNAME"], env2["CNAME"]
    assert cname1_before != cname2_before, (
        f"the two environments must be assigned distinct CNAMEs, both got {cname1_before!r}"
    )

    eb.swap_environment_cnames(SourceEnvironmentName=env1_name, DestinationEnvironmentName=env2_name)

    env1_after = _poll_until(
        lambda: eb.describe_environments(EnvironmentNames=[env1_name], IncludeDeleted=False)["Environments"][0],
        lambda e: e["CNAME"] == cname2_before,
        timeout_s=120.0,
        interval_s=10.0,
        what=f"environment {env1_name} reporting the swapped CNAME {cname2_before!r}",
    )
    env2_after = _poll_until(
        lambda: eb.describe_environments(EnvironmentNames=[env2_name], IncludeDeleted=False)["Environments"][0],
        lambda e: e["CNAME"] == cname1_before,
        timeout_s=120.0,
        interval_s=10.0,
        what=f"environment {env2_name} reporting the swapped CNAME {cname1_before!r}",
    )

    assert env1_after["CNAME"] == cname2_before, (
        f"env1 CNAME after swap is {env1_after['CNAME']!r}, expected env2's former CNAME {cname2_before!r}"
    )
    assert env2_after["CNAME"] == cname1_before, (
        f"env2 CNAME after swap is {env2_after['CNAME']!r}, expected env1's former CNAME {cname1_before!r}"
    )

    # CheckDNSAvailability only returns FullyQualifiedCNAME when Available is True (both fields are
    # modeled optional; measured on real AWS: the key is absent, not empty, once a prefix is taken).
    # Asserting its absence here is itself a fidelity check.
    dns1 = eb.check_dns_availability(CNAMEPrefix=prefix1)
    assert dns1["Available"] is False, (
        f"swapped CNAME prefix {prefix1!r} reports available even though env2 now uses it: {dns1!r}"
    )
    assert "FullyQualifiedCNAME" not in dns1, (
        f"real AWS omits FullyQualifiedCNAME once a prefix is taken; got {dns1!r}"
    )

    dns2 = eb.check_dns_availability(CNAMEPrefix=prefix2)
    assert dns2["Available"] is False, (
        f"swapped CNAME prefix {prefix2!r} reports available even though env1 now uses it: {dns2!r}"
    )
    assert "FullyQualifiedCNAME" not in dns2, (
        f"real AWS omits FullyQualifiedCNAME once a prefix is taken; got {dns2!r}"
    )


def _create_env_retrying_iam_propagation(eb, *, timeout_s: float = 300.0, **kwargs):
    """CreateEnvironment, bounded-retrying the transient refusal IAM issues while a just-created
    role/instance-profile has not yet propagated to EC2/Beanstalk. Any other error is raised
    immediately -- this is not a general-purpose retry."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eb.create_environment(**kwargs)
        except Exception as exc:  # noqa: BLE001 — inspecting message to isolate the propagation case
            msg = str(exc)
            if time.monotonic() >= deadline or not (
                "not have permission" in msg or "cannot be assumed" in msg
                or ("InvalidParameterValue" in msg and "role" in msg.lower())
            ):
                raise
            time.sleep(2)


def _ensure_env_iam(ctx):
    """Best-effort IAM instance profile + service role a SingleInstance environment needs to
    actually launch an EC2 instance. Without one, real AWS does not raise a deterministic
    error -- it parks the environment in Launching indefinitely (measured: 1200s, still
    Launching). Create-or-adopt idempotently; memoized on ctx so one check provisions IAM once
    for both environments. Returns (instance_profile|None, service_role|None); (None, None)
    when IAM is unreachable, so the check still exercises the Beanstalk path with the
    service's own defaults."""
    if hasattr(ctx, "_ebswap_iam"):
        return ctx._ebswap_iam
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:  # noqa: BLE001 — no IAM at all: let EB apply its defaults
        ctx._ebswap_iam = (None, None)
        return ctx._ebswap_iam

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        }
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                            Tags=[{"Key": "sim2real", "Value": CHECK}])
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

    ec2_role = ctx.unique_name("sim2real-ebswap-ec2-role-")
    svc_role = ctx.unique_name("sim2real-ebswap-svc-role-")
    profile = ctx.unique_name("sim2real-ebswap-profile-")
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
    # No fixed wait here: IAM exposes no signal for "a new role is now assumable by another
    # service", so _create_env_retrying_iam_propagation's bounded retry around CreateEnvironment
    # is what actually absorbs the propagation delay, with a real deadline and a specific error
    # match instead of a guess at how long it takes.
    ctx._ebswap_iam = (instance_profile, service_role)
    return ctx._ebswap_iam


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while True:
        if predicate(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last observed {value!r}")
        time.sleep(interval_s)
        value = probe()


def _wait_env_status(ctx, env_name: str, targets, timeout_s: float = 1200.0, interval_s: float = 20.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
