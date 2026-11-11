"""e2e-compose-swap-cnames-traffic-consequence."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-compose-swap-cnames-traffic-consequence"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """ComposeEnvironments builds two envs from one app; SwapEnvironmentCNAMEs
    actually swaps which environment serves which endpoint (observed via
    DescribeEnvironments), not just returns success."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-eb2-app-")
    name_a = ctx.unique_name("sim2real-eb2a-")
    name_b = ctx.unique_name("sim2real-eb2b-")
    cname_a = ctx.unique_name("sim2real-eb2a-").lower()
    cname_b = ctx.unique_name("sim2real-eb2b-").lower()
    label_a = ctx.unique_name("v-a-")
    label_b = ctx.unique_name("v-b-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    solution_stack = _pick_solution_stack(ctx)
    bucket = eb.create_storage_location()["S3Bucket"]
    profile, service_role = _eb_iam(ctx)

    for label, env_name, cname in ((label_a, name_a, cname_a), (label_b, name_b, cname_b)):
        manifest = _env_manifest(env_name, cname, solution_stack, profile, service_role)
        key = f"{app_name}/{label}.zip"
        s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes({"env.yaml": manifest}))
        eb.create_application_version(
            ApplicationName=app_name,
            VersionLabel=label,
            SourceBundle={"S3Bucket": bucket, "S3Key": key},
            Process=True,
        )
        ctx.on_cleanup(lambda version_label=label: eb.delete_application_version(ApplicationName=app_name, VersionLabel=version_label))
        _wait_version_processed(ctx, app_name, label)

    _compose_environments(ctx, eb, ApplicationName=app_name, VersionLabels=[label_a, label_b])
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=name_a))
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=name_b))

    # Both environments provision concurrently on AWS's side (one ComposeEnvironments call), so they
    # are polled together rather than one full 1800.0s wait after another; a single-instance
    # environment can take up to ~30 minutes to reach Ready.
    ready = _wait_until(
        lambda: {e["EnvironmentName"]: e for e in eb.describe_environments(EnvironmentNames=[name_a, name_b])["Environments"]},
        lambda envs: envs.get(name_a, {}).get("Status") == "Ready" and envs.get(name_b, {}).get("Status") == "Ready",
        timeout_s=1800.0,
        interval_s=20.0,
    )
    env_a, env_b = ready[name_a], ready[name_b]
    cname_a0, cname_b0 = env_a["CNAME"], env_b["CNAME"]
    assert cname_a0 and cname_b0 and cname_a0 != cname_b0, (
        f"the two composed environments must hold distinct, non-empty CNAMEs before any swap; "
        f"got {cname_a0!r} and {cname_b0!r}"
    )

    eb.swap_environment_cnames(SourceEnvironmentName=name_a, DestinationEnvironmentName=name_b)

    swapped = _wait_until(
        lambda: {e["EnvironmentName"]: e for e in eb.describe_environments(EnvironmentNames=[name_a, name_b])["Environments"]},
        lambda envs: envs.get(name_a, {}).get("CNAME") == cname_b0 and envs.get(name_b, {}).get("CNAME") == cname_a0,
        timeout_s=180.0,
    )
    assert swapped[name_a]["CNAME"] == cname_b0, (
        f"after SwapEnvironmentCNAMEs(source={name_a!r}, dest={name_b!r}), {name_a!r} must now "
        f"answer to {cname_b0!r} (the CNAME {name_b!r} held before the swap); "
        f"DescribeEnvironments still reports {swapped[name_a]['CNAME']!r}"
    )
    assert swapped[name_b]["CNAME"] == cname_a0, (
        f"after SwapEnvironmentCNAMEs(source={name_a!r}, dest={name_b!r}), {name_b!r} must now "
        f"answer to {cname_a0!r} (the CNAME {name_a!r} held before the swap); "
        f"DescribeEnvironments still reports {swapped[name_b]['CNAME']!r}"
    )


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _env_manifest(env_name: str, cname_prefix: str, solution_stack: str, profile: str | None, service_role: str | None) -> str:
    # ComposeEnvironments takes no OptionSettings of its own: each environment's options come
    # from its own version's env.yaml (saved-configuration format), so the instance profile and
    # service role a fresh sandbox account lacks by default have to be declared here.
    namespaces: dict[str, dict[str, str]] = {
        "aws:elasticbeanstalk:environment": {"EnvironmentType": "SingleInstance"},
    }
    if profile:
        namespaces.setdefault("aws:autoscaling:launchconfiguration", {})["IamInstanceProfile"] = profile
    if service_role:
        namespaces["aws:elasticbeanstalk:environment"]["ServiceRole"] = service_role

    lines = [
        "AWSConfigurationTemplateVersion: 1.1.0.0",
        f"SolutionStack: {solution_stack}",
        f"EnvironmentName: {env_name}",
        f"CName: {cname_prefix}",
        "OptionSettings:",
    ]
    for namespace, options in namespaces.items():
        lines.append(f"  {namespace}:")
        for option_name, value in options.items():
            lines.append(f"    {option_name}: {value}")
    return "\n".join(lines) + "\n"


def _eb_iam(ctx) -> tuple[str | None, str | None]:
    """The instance profile + service role a composed environment needs, with LIFO teardown.

    Returns (instance_profile|None, service_role|None); (None, None) when IAM is unreachable, so
    a target that serves no IAM still exercises the Beanstalk path with the service's own
    defaults. A fresh sandbox account has no "aws-elasticbeanstalk-*" default role, so
    ComposeEnvironments launches an environment that terminates itself within seconds if none is
    supplied.
    """
    iam = ctx.client("iam")
    try:
        iam.list_roles(MaxItems=1)
    except Exception:  # noqa: BLE001 — no IAM at all: let EB apply its defaults
        return None, None

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policies:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-eb2-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb2-svc-role-")
    profile = ctx.unique_name("sim2real-eb2-profile-")
    _role(ec2_role, "ec2.amazonaws.com",
          ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"])
    _role(svc_role, "elasticbeanstalk.amazonaws.com",
          ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
           "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"])
    iam.create_instance_profile(InstanceProfileName=profile)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile, RoleName=ec2_role))
    # IAM exposes no condition that reports a principal has become usable by another service, so
    # there is nothing to poll here; the bounded retry in _compose_environments is what makes an
    # immediate ComposeEnvironments call correct rather than lucky if IAM has not yet propagated.
    return profile, svc_role


def _compose_environments(ctx, eb, **kwargs):
    """ComposeEnvironments with a bounded retry over the IAM-propagation refusal."""
    deadline = time.monotonic() + 300
    while True:
        try:
            return eb.compose_environments(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if time.monotonic() >= deadline or not (
                    "not have permission" in msg or "cannot be assumed" in msg
                    or ("InvalidParameterValue" in msg and "role" in msg.lower())):
                raise
            time.sleep(2)


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    matches = [s for s in stacks if "Node.js" in s and "Docker" not in s]
    if not matches:
        raise AssertionError("no Node.js (non-Docker) solution stack available in this region")
    return matches[0]


def _wait_until(probe, predicate, timeout_s: float, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last observed={last!r}")


def _wait_version_processed(ctx, app_name: str, label: str):
    # Real AWS answers this field in UPPERCASE ("PROCESSED") while the Smithy model spells the enum
    # title-case ("Processed"). Compare case-folded, as every other check in this directory already
    # does.
    eb = ctx.client("elasticbeanstalk")

    def _probe():
        versions = eb.describe_application_versions(ApplicationName=app_name, VersionLabels=[label])["ApplicationVersions"]
        return versions[0] if versions else None

    result = _wait_until(
        _probe,
        lambda v: v is not None and (v.get("Status") or "").upper() in ("PROCESSED", "FAILED", "UNPROCESSED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert (result["Status"] or "").upper() == "PROCESSED", f"version {label!r} must process, got {result['Status']!r}"
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
