"""compose-environments-creates-envs-from-versions-lifecycle."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags

CHECK = "compose-environments-creates-envs-from-versions-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ComposeEnvironments creates one environment per application version's env.yaml manifest,
    each going Launching -> Ready, with the tier (WebServer vs Worker) taken from the manifest."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-eb-app-")[:100]
    group = "g" + uuid.uuid4().hex[:10]  # GroupName max length is 19
    stack = _pick_solution_stack(ctx)
    instance_profile, service_role = _ensure_env_iam(ctx)

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    bucket = eb.create_storage_location()["S3Bucket"]
    prefix = f"sim2real-eb-compose/{uuid.uuid4().hex}"

    front_key = f"{prefix}/front.zip"
    worker_key = f"{prefix}/worker.zip"
    s3.put_object(
        Bucket=bucket,
        Key=front_key,
        Body=_manifest_bundle("front", "WebServer", "Standard", stack, instance_profile, service_role),
    )
    s3.put_object(
        Bucket=bucket,
        Key=worker_key,
        Body=_manifest_bundle("worker", "Worker", "SQS/HTTP", stack, instance_profile, service_role),
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=front_key))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=worker_key))

    front_label = "front-v1"
    worker_label = "worker-v1"
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=front_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": front_key},
        Process=True,
    )
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=worker_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": worker_key},
        Process=True,
    )
    _wait_version_processed(ctx, app_name, front_label, timeout_s=180.0)
    _wait_version_processed(ctx, app_name, worker_label, timeout_s=180.0)

    # ComposeEnvironments materializes environments asynchronously, so its own response may list
    # none, some or all of them; poll and match on VersionLabel, the identifier it guarantees.
    compose_resp = _retry_over_iam_propagation(ctx, lambda: eb.compose_environments(
        ApplicationName=app_name, GroupName=group, VersionLabels=[front_label, worker_label]
    ))
    immediate_labels = {e["VersionLabel"] for e in compose_resp.get("Environments", [])}
    assert immediate_labels <= {front_label, worker_label}, (
        f"compose_environments returned an environment for a version label outside this request: "
        f"{immediate_labels - {front_label, worker_label}}"
    )

    by_version = _wait_all_ready(ctx, app_name, [front_label, worker_label], timeout_s=900.0)
    front_env, worker_env = by_version[front_label], by_version[worker_label]
    assert front_env["EnvironmentName"] != worker_env["EnvironmentName"], (
        "front and worker versions were composed into the same environment"
    )
    assert front_env["Tier"]["Name"] == "WebServer", (
        f"expected the front environment's tier to be WebServer (from its manifest), got {front_env['Tier']['Name']}"
    )
    assert worker_env["Tier"]["Name"] == "Worker", (
        f"expected the worker environment's tier to be Worker (from its manifest), got {worker_env['Tier']['Name']}"
    )
    assert front_env["Tier"]["Type"] == "Standard", (
        f"expected the front environment's tier type to be Standard (from its manifest), got {front_env['Tier']['Type']}"
    )
    assert worker_env["Tier"]["Type"] == "SQS/HTTP", (
        f"expected the worker environment's tier type to be SQS/HTTP (from its manifest), got {worker_env['Tier']['Type']}"
    )


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Amazon Linux 2" in s and "Windows" not in s:
            return s
    if not stacks:
        raise AssertionError("no Elastic Beanstalk solution stacks available in this region/account")
    return stacks[0]


def _ensure_env_iam(ctx) -> tuple[str | None, str | None]:
    """Idempotently create the EC2 instance profile + EB service role an environment needs; without
    them ComposeEnvironments produces no environment at all; the compose call retries over their
    propagation. Returns (None, None) if IAM is unreachable, letting the service apply its defaults."""
    if hasattr(ctx, "_eb_iam"):
        return ctx._eb_iam
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        ctx._eb_iam = (None, None)
        return ctx._eb_iam

    def _create_role(name: str, service: str, policy_arns: list[str]) -> bool:
        trust = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
            }
        )
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)
        except Exception as exc:  # noqa: BLE001 -- already-exists is fine
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

    ec2_role = ctx.unique_name("sim2real-eb-compose-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-compose-svc-role-")
    profile = ctx.unique_name("sim2real-eb-compose-profile-")
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
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


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


def _manifest_bundle(
    name: str,
    tier_name: str,
    tier_type: str,
    stack: str,
    instance_profile: str | None,
    service_role: str | None,
) -> bytes:
    option_settings: dict[str, dict[str, str]] = {
        "aws:elasticbeanstalk:environment": {"EnvironmentType": "SingleInstance"},
        "aws:autoscaling:launchconfiguration": {"InstanceType": "t3.micro"},
    }
    if instance_profile:
        option_settings["aws:autoscaling:launchconfiguration"]["IamInstanceProfile"] = instance_profile
    if service_role:
        option_settings["aws:elasticbeanstalk:environment"]["ServiceRole"] = service_role
        option_settings["aws:elasticbeanstalk:healthreporting:system"] = {"SystemType": "enhanced"}

    option_lines = ["OptionSettings:"]
    for namespace, opts in option_settings.items():
        option_lines.append(f"  {namespace}:")
        option_lines.extend(f"    {k}: {v}" for k, v in opts.items())

    env_yaml = "\n".join(
        [
            "AWSConfigurationTemplateVersion: 1.1.0.0",
            f"EnvironmentName: {name}+",
            "EnvironmentTier:",
            f"  Name: {tier_name}",
            f"  Type: {tier_type}",
            f'SolutionStack: "{stack}"',
            *option_lines,
            "",
        ]
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("env.yaml", env_yaml)
        zf.writestr("index.html", f"<html><body>{name}</body></html>")
    return buf.getvalue()


def _wait_version_processed(ctx, app: str, label: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> None:
    # ApplicationVersionStatus is UPPERCASE on the wire ("PROCESSED") while the Smithy enum spells
    # it "Processed" / "Failed"; comparisons below normalise case for that reason only.
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        versions = eb.describe_application_versions(ApplicationName=app, VersionLabels=[label])["ApplicationVersions"]
        if versions:
            last = versions[0]["Status"]
            if last.upper() in ("PROCESSED", "FAILED"):
                assert last.upper() == "PROCESSED", f"application version {label} failed processing: {last}"
                return
        time.sleep(interval_s)
    raise AssertionError(f"application version {label} never finished processing; last status={last}")


def _wait_all_ready(ctx, app: str, version_labels: list[str], timeout_s: float = 900.0, interval_s: float = 2.0) -> dict:
    """Poll until every version label has a Ready environment; returns {version_label: env}.
    Matches on VersionLabel, which ComposeEnvironments guarantees, not a guessed EnvironmentName."""
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_by_label: dict[str, dict] = {}
    while time.monotonic() < deadline:
        envs = eb.describe_environments(ApplicationName=app, IncludeDeleted=False)["Environments"]
        last_by_label = {e["VersionLabel"]: e for e in envs if e.get("VersionLabel") in version_labels}
        if len(last_by_label) == len(version_labels) and all(
            e["Status"] == "Ready" for e in last_by_label.values()
        ):
            return last_by_label
        time.sleep(interval_s)
    statuses = {label: e.get("Status") for label, e in last_by_label.items()}
    raise AssertionError(f"composed environments never all reached Ready; last statuses={statuses}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
