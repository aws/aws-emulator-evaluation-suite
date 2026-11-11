"""compose-environments-concurrent-launch-no-duplicate-envs."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compose-environments-concurrent-launch-no-duplicate-envs"
GROUP = "concurrency"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent ComposeEnvironments calls for the same version, whose env.yaml names one environment,
    both succeed and converge to exactly one environment id, Ready once."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-cenv-")
    version_label = ctx.unique_name("sim2real-eb-ver-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "compose-environments-concurrent-launch-no-duplicate-envs"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    svc_role_name, _svc_role_arn, ec2_profile_name = _create_eb_roles(ctx)
    solution_stack = _pick_solution_stack(eb)

    bundle = _build_env_yaml_bundle(env_name, solution_stack, svc_role_name, ec2_profile_name)
    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{ctx.unique_name('sim2real-eb-bundle-')}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=bundle, Tagging="sim2real=compose-environments-concurrent-launch-no-duplicate-envs")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        Process=True,
        Tags=[{"Key": "sim2real", "Value": "compose-environments-concurrent-launch-no-duplicate-envs"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application_version(
        ApplicationName=app_name, VersionLabel=version_label, DeleteSourceBundle=False))
    version_status = _wait_version_processed(eb, app_name, version_label)
    assert version_status.upper() == "PROCESSED", f"application version {version_label} must process, got {version_status!r}"

    def _compose() -> tuple[list[str], str | None]:
        deadline = time.monotonic() + 300.0
        while True:
            try:
                resp = eb.compose_environments(ApplicationName=app_name, VersionLabels=[version_label])
                return [e["EnvironmentId"] for e in resp.get("Environments", [])], None
            except ClientError as err:
                code = err.response["Error"]["Code"]
                msg = err.response["Error"].get("Message", "")
                if code != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                    return [], f"{code}: {msg}"
                time.sleep(5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(_compose), pool.submit(_compose)]]

    for _ids, code in results:
        assert code is None, f"unexpected ComposeEnvironments failure: {code}"

    _wait_env_status(eb, env_name, targets={"Ready"}, timeout_s=900.0)

    all_envs = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[env_name], IncludeDeleted=True
    )["Environments"]
    distinct_ids = {e["EnvironmentId"] for e in all_envs}
    assert len(distinct_ids) == 1, f"expected exactly one environment ever created for {env_name}, got ids={distinct_ids}"

    ready_envs = [e for e in all_envs if e["Status"] == "Ready"]
    assert len(ready_envs) == 1, f"expected exactly one Ready environment named {env_name}, got {ready_envs}"


def _build_env_yaml_bundle(env_name: str, solution_stack: str, svc_role_name: str, ec2_profile_name: str) -> bytes:
    manifest = (
        "AWSConfigurationTemplateVersion: 1.1.0.0\n"
        f"SolutionStack: {solution_stack}\n"
        f"EnvironmentName: {env_name}\n"
        "OptionSettings:\n"
        "  aws:elasticbeanstalk:environment:\n"
        f"    ServiceRole: {svc_role_name}\n"
        "    EnvironmentType: SingleInstance\n"
        "  aws:autoscaling:launchconfiguration:\n"
        f"    IamInstanceProfile: {ec2_profile_name}\n"
        "    InstanceType: t3.micro\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("env.yaml", manifest)
    return buf.getvalue()


def _create_eb_roles(ctx) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-ebrole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )

    svc_role_arn = iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return svc_name, svc_role_arn, ec2_name


def _wait_version_processed(eb, app_name: str, version_label: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = eb.describe_application_versions(
            ApplicationName=app_name, VersionLabels=[version_label]
        )["ApplicationVersions"][0]["Status"]
        if status.upper() != "PROCESSING":
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"application version {version_label} still Processing after {timeout_s}s")
        time.sleep(interval_s)


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for stack in stacks:
        if "Amazon Linux 2" in stack and "Docker" not in stack and "Windows" not in stack:
            return stack
    return stacks[0]


def _wait_env_status(eb, env_name: str, targets: set[str], timeout_s: float = 900.0, interval_s: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    status = last.get("Status") if last else None
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
