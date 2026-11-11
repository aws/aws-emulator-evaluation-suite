"""e2e-compose-multi-tier-application-environments."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags

CHECK = "e2e-compose-multi-tier-application-environments"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("cap:c1", "cap:c4", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """ComposeEnvironments with two env.yaml-bearing versions returns an empty Environments list and creates neither
    environment, while CreateEnvironment on the same solution stack and IAM setup reaches Ready."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-behav-compose-")
    group = "s2r" + uuid.uuid4().hex[:8]

    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    bucket = eb.create_storage_location()["S3Bucket"]
    stack = _pick_solution_stack(eb)
    instance_profile, service_role = _ensure_env_iam(ctx)

    front_ns = {"aws:elasticbeanstalk:environment": {"EnvironmentType": "SingleInstance"}}
    worker_ns: dict[str, dict[str, str]] = {}
    if service_role:
        front_ns["aws:elasticbeanstalk:environment"]["ServiceRole"] = service_role
        worker_ns["aws:elasticbeanstalk:environment"] = {"ServiceRole": service_role}
    if instance_profile:
        front_ns["aws:autoscaling:launchconfiguration"] = {"IamInstanceProfile": instance_profile}
        worker_ns["aws:autoscaling:launchconfiguration"] = {"IamInstanceProfile": instance_profile}

    front_manifest = f"""AWSConfigurationTemplateVersion: 1.1.0.0
SolutionStack: {stack}
EnvironmentName: front+
EnvironmentTier:
  Name: WebServer
  Type: Standard
EnvironmentLinks:
  "WORKERQUEUE": "worker+"
{_option_settings_yaml(front_ns)}"""
    worker_manifest = f"""AWSConfigurationTemplateVersion: 1.1.0.0
SolutionStack: {stack}
EnvironmentName: worker+
EnvironmentTier:
  Name: Worker
  Type: SQS/HTTP
{_option_settings_yaml(worker_ns)}"""

    front_version = f"front-{group}"
    worker_version = f"worker-{group}"
    _upload_manifest_version(ctx, eb, s3, bucket, app_name, front_version, front_manifest)
    _upload_manifest_version(ctx, eb, s3, bucket, app_name, worker_version, worker_manifest)

    # Positive control: the SAME stack and IAM prerequisites, via the ordinary
    # (non-compose) API, reaches Ready -- so a failure below is ComposeEnvironments'
    # manifest path, not a broken account (missing default VPC, missing default EB
    # service roles, quota, ...).
    control_env_name = ctx.unique_name("sim2real-ctrl-")[:40]
    control_options = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    if instance_profile:
        control_options.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        control_options.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=control_env_name,
        # No VersionLabel: deploys the platform's own built-in sample application, so
        # this measures whether the ACCOUNT can reach Ready at all -- not whether our
        # manifest-only (no runnable app) bundle can, which is a different question.
        SolutionStackName=stack,
        OptionSettings=control_options,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=control_env_name))
    control = _wait_for_env_status(eb, control_env_name, {"Ready", "Terminated"}, timeout_s=900)
    assert control["Status"] == "Ready", (
        f"positive control environment {control_env_name!r} on stack {stack!r} entered "
        f"{control['Status']!r} instead of Ready -- the account/stack is not healthy for "
        "plain CreateEnvironment, so a ComposeEnvironments failure below cannot be pinned on "
        "ComposeEnvironments specifically"
    )

    compose_resp = eb.compose_environments(
        ApplicationName=app_name, GroupName=group, VersionLabels=[front_version, worker_version]
    )
    composed = {e["VersionLabel"]: e["EnvironmentName"] for e in compose_resp.get("Environments", [])}
    assert composed == {}, (
        "ComposeEnvironments reported environments for a doc-conformant two-tier manifest set "
        f"({composed!r}) -- if this stack's ComposeEnvironments support has been restored, this "
        "check's contract (asserting the withdrawal) is stale and should be rewritten back to "
        "asserting the linked environments themselves reach Ready with EnvironmentLinks wired."
    )

    front_env_name = f"front-{group}"
    worker_env_name = f"worker-{group}"
    remaining = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[front_env_name, worker_env_name], IncludeDeleted=False
    ).get("Environments", [])
    assert remaining == [], (
        f"ComposeEnvironments reported no environments, yet DescribeEnvironments finds {remaining!r} "
        f"under the names the manifests requested ({front_env_name!r}, {worker_env_name!r})"
    )


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _ensure_env_iam(ctx):
    """Best-effort: create the EC2 instance profile + EB service role a fresh sandbox
    account lacks by default, registering LIFO teardown. Returns
    (instance_profile|None, service_role|None); degrades to (None, None) when IAM is
    unreachable, letting the service apply whatever defaults it has. Memoized on ctx."""
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
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        except Exception as exc:  # noqa: BLE001 - already-exists is fine
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
    ec2_ok = _create_role(ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"])
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
                    lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                )
            except Exception:  # noqa: BLE001
                pass
            instance_profile = profile
    # IAM is eventually consistent: confirm the instance profile is actually visible via a
    # read (not just that CreateInstanceProfile 200'd) before EB is asked to reference it,
    # bounded rather than a blind sleep.
    if instance_profile:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            try:
                iam.get_instance_profile(InstanceProfileName=instance_profile)
                break
            except Exception:  # noqa: BLE001
                time.sleep(2)
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _option_settings_yaml(namespaces: dict[str, dict[str, str]]) -> str:
    """Render an env.yaml OptionSettings block from {namespace: {option: value}},
    merging same-namespace options into one mapping so the manifest never carries a
    duplicate YAML key -- naive string concatenation of two separately-authored
    blocks under the same namespace would produce exactly that, and a real-AWS
    manifest parser can reject or silently ignore the whole file over it."""
    if not any(namespaces.values()):
        return ""
    lines = ["OptionSettings:"]
    for ns, opts in namespaces.items():
        if not opts:
            continue
        lines.append(f"  {ns}:")
        for key, value in opts.items():
            lines.append(f"    {key}: {value}")
    return "\n".join(lines) + "\n"


def _upload_manifest_version(ctx, eb, s3, bucket: str, app_name: str, version_label: str, manifest_text: str) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("env.yaml", manifest_text)
    key = f"sim2real-compose/{version_label}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        Process=True,
    )
    # No separate cleanup for the version here: it is about to be deployed to
    # an environment, and DeleteApplication(TerminateEnvByForce=True) (already
    # registered by the caller) cascades to both the environments and their
    # application versions once torn down.
    _wait_for_version_processed(eb, app_name, version_label)


def _wait_for_version_processed(eb, app_name: str, version_label: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        versions = eb.describe_application_versions(
            ApplicationName=app_name, VersionLabels=[version_label]
        ).get("ApplicationVersions", [])
        if versions:
            last = versions[0]["Status"]
            # Real AWS returns this status ALL-CAPS ("PROCESSED"/"FAILED"), not the title-case the
            # Smithy model documents.
            if last.upper() in ("PROCESSED", "FAILED"):
                assert last.upper() == "PROCESSED", f"{version_label} failed processing: {last}"
                return
        time.sleep(interval_s)
    raise AssertionError(f"application version {version_label} never finished processing; last={last}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
