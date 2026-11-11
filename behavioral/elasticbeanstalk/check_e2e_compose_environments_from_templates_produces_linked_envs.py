"""e2e-compose-environments-from-templates-produces-linked-envs."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "e2e-compose-environments-from-templates-produces-linked-envs"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ComposeEnvironments from a version whose env.yaml sets InstanceType yields one environment
    named <manifest-prefix>-<group-name> that reaches Ready with that InstanceType."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-ebcompose-app-")
    template_name = ctx.unique_name("sim2real-ebcompose-tmpl-")
    instance_type = "t3.micro"

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(ctx)
    instance_profile = _ensure_instance_profile(ctx)
    template_option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": instance_type},
    ]
    if instance_profile:
        template_option_settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    # The template only mirrors the setting; the env.yaml manifest does not reference it.
    eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=stack,
        OptionSettings=template_option_settings,
    )
    ctx.on_cleanup(lambda: eb.delete_configuration_template(ApplicationName=app_name, TemplateName=template_name))

    bucket = eb.create_storage_location()["S3Bucket"]
    group_name = _short_id(ctx, 6)
    env_prefix = f"cmp{_short_id(ctx, 7)}"

    manifest_lines = [
        "AWSConfigurationTemplateVersion: 1.1.0.0",
        f"SolutionStack: {stack}",
        "OptionSettings:",
        "  aws:autoscaling:launchconfiguration:",
        f"    InstanceType: {instance_type}",
    ]
    if instance_profile:
        manifest_lines.append(f"    IamInstanceProfile: {instance_profile}")
    manifest_lines += [
        "  aws:elasticbeanstalk:environment:",
        "    EnvironmentType: SingleInstance",
        f"EnvironmentName: {env_prefix}+",
    ]
    manifest = "\n".join(manifest_lines)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("env.yaml", manifest)
    buf.seek(0)

    version_label = ctx.unique_name("sim2real-ebcompose-v-")
    key = f"{app_name}/{version_label}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        Process=True,
    )
    ctx.on_cleanup(lambda: eb.delete_application_version(ApplicationName=app_name, VersionLabel=version_label))

    _wait_version_processed(ctx, app_name, version_label, timeout_s=180.0, interval_s=2.0)

    _retry_over_iam_propagation(ctx, lambda: eb.compose_environments(
        ApplicationName=app_name, GroupName=group_name, VersionLabels=[version_label]))

    composed_name = _discover_composed_env_name(ctx, app_name, timeout_s=120.0, interval_s=2.0)
    assert composed_name == f"{env_prefix}-{group_name}", (
        f"composed environment name {composed_name!r} does not follow the documented "
        f"'<manifest-prefix>-<group-name>' convention for {env_prefix!r}/{group_name!r}"
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=composed_name))

    env = _wait_env_status(ctx, composed_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"composed environment entered {env['Status']} instead of Ready"
    assert env["ApplicationName"] == app_name

    settings = eb.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=composed_name)[
        "ConfigurationSettings"
    ][0]["OptionSettings"]
    matching = [
        o
        for o in settings
        if o["Namespace"] == "aws:autoscaling:launchconfiguration" and o["OptionName"] == "InstanceType"
    ]
    assert matching, "composed environment has no InstanceType option setting at all"
    assert matching[0]["Value"] == instance_type, (
        f"composed environment InstanceType is {matching[0]['Value']!r}, expected the manifest-inherited "
        f"{instance_type!r} (mirroring the saved configuration template's setting)"
    )


def _short_id(ctx, n: int) -> str:
    raw = ctx.unique_name("x")
    return "".join(c for c in raw if c.isalnum())[-n:].lower()


def _ensure_instance_profile(ctx) -> str | None:
    """Create an instance profile with the EB web-tier policy; a composed environment fails without one.
    The compose call retries over its propagation. Returns the profile name, or None when IAM is
    unreachable so the service applies defaults."""
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        return None

    role_name = ctx.unique_name("sim2real-ebcompose-ec2-role-")
    profile_name = ctx.unique_name("sim2real-ebcompose-ec2-profile-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    return profile_name


#: Bound for fresh IAM roles and instance profiles to become usable by Elastic Beanstalk.
_IAM_PROPAGATION_S = 120.0


def _deadline(ctx, budget_s):
    """A monotonic deadline `budget_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (budget_s if left is None else min(budget_s, max(0.0, left - 5)))


def _iam_not_yet_usable(message: str) -> bool:
    """An Elastic Beanstalk refusal of a role or instance profile that IAM has not yet propagated."""
    low = message.lower()
    return ("insufficientprivileges" in low or "not have permission" in low
            or "cannot be assumed" in low or "unable to assume" in low
            or ("instance profile" in low and ("not exist" in low or "invalid" in low))
            or ("invalidparametervalue" in low and "role" in low))


def _retry_over_iam_propagation(ctx, call):
    """Run `call`, retrying every 2 s while it fails on a not-yet-propagated principal."""
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the propagation refusal
            if time.monotonic() >= deadline or not _iam_not_yet_usable(f"{type(exc).__name__} {exc}"):
                raise
        time.sleep(2)


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _wait_version_processed(ctx, app_name: str, version_label: str, *, timeout_s: float, interval_s: float) -> None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        versions = eb.describe_application_versions(ApplicationName=app_name, VersionLabels=[version_label])[
            "ApplicationVersions"
        ]
        if versions:
            last = versions[0]["Status"]
            if last.upper() in ("PROCESSED", "FAILED"):
                assert last.upper() == "PROCESSED", (
                    f"application version {version_label} processing ended in {last!r}"
                )
                return
        time.sleep(interval_s)
    raise AssertionError(f"application version {version_label} never finished processing; last status={last!r}")


def _discover_composed_env_name(ctx, app_name: str, *, timeout_s: float, interval_s: float) -> str:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_count = 0
    while time.monotonic() < deadline:
        envs = eb.describe_environments(ApplicationName=app_name, IncludeDeleted=False).get("Environments", [])
        last_count = len(envs)
        if last_count == 1:
            return envs[0]["EnvironmentName"]
        if last_count > 1:
            raise AssertionError(f"expected exactly one composed environment, got {[e['EnvironmentName'] for e in envs]}")
        time.sleep(interval_s)
    events = [
        f"{e['Severity']}: {e['Message']}"
        for e in eb.describe_events(ApplicationName=app_name, MaxRecords=20).get("Events", [])
    ]
    raise AssertionError(
        f"no composed environment appeared under {app_name!r} within {timeout_s}s "
        f"(last count={last_count}); recent events: {events}"
    )


def _wait_env_status(ctx, env_name: str, targets, timeout_s: float = 1200.0, interval_s: float = 2.0):
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
