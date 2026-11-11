"""e2e-swap-cname-then-verify-dns-and-traffic-consequence."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-swap-cname-then-verify-dns-and-traffic-consequence"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SwapEnvironmentCNAMEs exchanges two environments' CNAMEs while keeping their EnvironmentIds,
    and afterwards CheckDNSAvailability reports both original prefixes Available=True."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-swap-")
    env_a = ctx.unique_name("sim2real-swp-a-")
    env_b = ctx.unique_name("sim2real-swp-b-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    option_settings = _env_option_settings(ctx)
    for name in (env_a, env_b):
        eb.create_environment(
            ApplicationName=app_name,
            EnvironmentName=name,
            SolutionStackName=stack,
            Tags=[{"Key": "sim2real", "Value": "true"}],
            OptionSettings=option_settings,
        )

    before_a = _wait_for_env_status(eb, env_a, {"Ready"}, timeout_s=900)
    before_b = _wait_for_env_status(eb, env_b, {"Ready"}, timeout_s=900)
    cname_a, cname_b = before_a["CNAME"], before_b["CNAME"]
    assert cname_a != cname_b, f"env_a and env_b were issued the same CNAME: {cname_a!r}"

    eb.swap_environment_cnames(SourceEnvironmentName=env_a, DestinationEnvironmentName=env_b)

    after_a, after_b = _wait_for_cname_swap(eb, env_a, env_b, cname_a, cname_b, timeout_s=180)

    # Identity is preserved -- only the CNAME moved, not the environment itself.
    assert after_a["EnvironmentId"] == before_a["EnvironmentId"], (
        f"env_a identity changed across swap: before={before_a['EnvironmentId']!r} "
        f"after={after_a['EnvironmentId']!r}"
    )
    assert after_b["EnvironmentId"] == before_b["EnvironmentId"], (
        f"env_b identity changed across swap: before={before_b['EnvironmentId']!r} "
        f"after={after_b['EnvironmentId']!r}"
    )
    assert after_a["CNAME"] == cname_b, (
        f"env_a CNAME after swap is {after_a['CNAME']!r}, expected env_b's former CNAME {cname_b!r}"
    )
    assert after_b["CNAME"] == cname_a, (
        f"env_b CNAME after swap is {after_b['CNAME']!r}, expected env_a's former CNAME {cname_a!r}"
    )

    # AWS quirk: the swap releases each prefix's reservation without transferring it, so both
    # report Available=True even though each now serves the other environment.
    prefix_a = cname_a.split(".")[0]
    prefix_b = cname_b.split(".")[0]
    dns_a = eb.check_dns_availability(CNAMEPrefix=prefix_a)
    dns_b = eb.check_dns_availability(CNAMEPrefix=prefix_b)
    assert dns_a["Available"] is True, (
        f"prefix_a {prefix_a!r} still reports held after the swap released its reservation: {dns_a}"
    )
    assert dns_b["Available"] is True, (
        f"prefix_b {prefix_b!r} still reports held after the swap released its reservation: {dns_b}"
    )


def _ensure_env_iam(ctx):
    """Best-effort create of the instance profile and service role CreateEnvironment needs.

    Returns (None, None) when IAM is unreachable; only the console creates the default roles."""
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

    ec2_role = ctx.unique_name("sim2real-behav-eb-swap-ec2-role-")
    svc_role = ctx.unique_name("sim2real-behav-eb-swap-service-role-")
    profile = ctx.unique_name("sim2real-behav-eb-swap-ec2-profile-")
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
    if instance_profile:
        _wait_for_role_in_instance_profile(iam, instance_profile, ec2_role, timeout_s=60)
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _wait_for_role_in_instance_profile(iam, profile: str, role: str, *, timeout_s: float, interval_s: float = 3.0):
    """Poll until the just-attached role is visible on the instance profile (IAM is eventually
    consistent, and CreateEnvironment may otherwise read the profile without it)."""
    deadline = time.monotonic() + timeout_s
    last_roles = []
    while time.monotonic() < deadline:
        last_roles = [
            r["RoleName"]
            for r in iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"]
        ]
        if role in last_roles:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"instance profile {profile!r} never showed role {role!r} attached within {timeout_s}s; "
        f"last roles={last_roles}"
    )


def _env_option_settings(ctx):
    """Baseline option settings that make a single-instance environment launch, with an
    IAM-provisioned instance profile merged in when IAM is reachable."""
    instance_profile, service_role = _ensure_env_iam(ctx)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
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
    events = eb.describe_events(EnvironmentName=env_name, MaxRecords=10).get("Events", [])
    raise AssertionError(
        f"environment {env_name} never reached {statuses}; last={last}; "
        f"recent events={[(e.get('Severity'), e.get('Message')) for e in events]}"
    )


def _wait_for_cname_swap(eb, env_a: str, env_b: str, cname_a: str, cname_b: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_a = last_b = None
    while time.monotonic() < deadline:
        envs = {
            e["EnvironmentName"]: e
            for e in eb.describe_environments(
                EnvironmentNames=[env_a, env_b], IncludeDeleted=False
            ).get("Environments", [])
        }
        last_a, last_b = envs.get(env_a), envs.get(env_b)
        if last_a and last_b and last_a["CNAME"] == cname_b and last_b["CNAME"] == cname_a:
            return last_a, last_b
        time.sleep(interval_s)
    raise AssertionError(f"CNAMEs never swapped; last_a={last_a}, last_b={last_b}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
