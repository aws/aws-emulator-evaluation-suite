"""e2e-compose-environments-then-terminate-cleans-up."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-compose-environments-then-terminate-cleans-up"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Environments created by ComposeEnvironments from env.yaml-bearing bundles are first-class: each
    one terminates individually through TerminateEnvironment and then leaves DescribeEnvironments.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    # One teardown deadline per run, started by the first teardown that asks for it.
    teardown: dict = {}

    app_name = ctx.unique_name("sim2real-eb-app-")[:100]
    group = "g" + uuid.uuid4().hex[:10]  # GroupName max length is 19
    version_a = ctx.unique_name("sim2real-eb-ver-a-")
    version_b = ctx.unique_name("sim2real-eb-ver-b-")

    eb.create_application(
        ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: _delete_app(eb, app_name))

    # An environment needs a service role and an EC2 instance profile to reach Ready.
    svc_role_name, ec2_profile_name = _create_eb_roles(ctx)
    # The instances sit in the run's network behind a group of the check's own with no inbound
    # rule, in place of EB's default group that opens port 80 to 0.0.0.0/0.
    network = ctx.network()
    sg_id = _create_closed_security_group(ctx, network.vpc_id, teardown)
    placement = (network.vpc_id, ",".join(network.subnet_ids), sg_id)
    stack = _pick_solution_stack(eb)
    bucket = eb.create_storage_location()["S3Bucket"]

    key_a = f"{app_name}/{version_a}.zip"
    key_b = f"{app_name}/{version_b}.zip"
    s3.put_object(Bucket=bucket, Key=key_a, Body=_build_env_yaml_zip("cmpa", stack, svc_role_name, ec2_profile_name, placement))
    s3.put_object(Bucket=bucket, Key=key_b, Body=_build_env_yaml_zip("cmpb", stack, svc_role_name, ec2_profile_name, placement))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key_a))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key_b))

    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_a,
        SourceBundle={"S3Bucket": bucket, "S3Key": key_a},
        Process=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_b,
        SourceBundle={"S3Bucket": bucket, "S3Key": key_b},
        Process=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    _wait_version_processed(eb, app_name, version_a, timeout_s=180.0)
    _wait_version_processed(eb, app_name, version_b, timeout_s=180.0)

    compose_resp = eb.compose_environments(
        ApplicationName=app_name, GroupName=group, VersionLabels=[version_a, version_b]
    )
    # ComposeEnvironments can answer before its environments are listed; DescribeEnvironments shows
    # them shortly after. Every environment found gets its teardown before the assert.
    env_descs = {e["EnvironmentName"]: e for e in compose_resp["Environments"]}
    if len(env_descs) < 2:
        env_descs = _poll_composed(ctx, eb, app_name)
    composed = sorted(env_descs)
    ctx.on_cleanup(lambda: _terminate_envs_and_wait(eb, composed, teardown))
    assert len(env_descs) == 2, (
        f"expected 2 composed environments, got {sorted(env_descs)}; stack={stack!r}; "
        f"full ComposeEnvironments response={compose_resp!r}"
    )
    env_names = sorted(env_descs)
    env_a = next(n for n in env_names if n.startswith("cmpa"))
    env_b = next(n for n in env_names if n.startswith("cmpb"))

    envs = _wait_for_envs_status(eb, [env_a, env_b], {"Ready"}, timeout_s=900.0)
    # ComposeEnvironments has no Tags param; UpdateTagsForResource, which needs a Ready
    # environment and starts a deployment on it, is the only way to tag a composed environment.
    for e in env_descs.values():
        eb.update_tags_for_resource(
            ResourceArn=e["EnvironmentArn"], TagsToAdd=[{"Key": "sim2real", "Value": "true"}]
        )
    assert envs[env_a]["ApplicationName"] == app_name
    assert envs[env_b]["ApplicationName"] == app_name

    # Each composed environment can be individually terminated and disappears
    # from the default (non-deleted) DescribeEnvironments view.
    _terminate_when_accepted(eb, env_a, timeout_s=600.0)
    _poll_until_absent(eb, env_a, timeout_s=600.0)

    still_there = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[env_b], IncludeDeleted=False
    )["Environments"]
    assert len(still_there) == 1 and still_there[0]["Status"] != "Terminated"

    _terminate_when_accepted(eb, env_b, timeout_s=600.0)
    _poll_until_absent(eb, env_b, timeout_s=600.0)


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    return stacks[0]


def _build_env_yaml_zip(
    name_prefix: str, stack: str, svc_role_name: str, ec2_profile_name: str, placement: tuple[str, str, str]
) -> bytes:
    vpc_id, subnets, sg_id = placement
    manifest = (
        "AWSConfigurationTemplateVersion: 1.1.0.0\n"
        f"EnvironmentName: {name_prefix}+\n"
        "EnvironmentTier:\n"
        "  Name: WebServer\n"
        "  Type: Standard\n"
        f'SolutionStack: "{stack}"\n'
        "OptionSettings:\n"
        "  aws:elasticbeanstalk:environment:\n"
        f"    ServiceRole: {svc_role_name}\n"
        "    EnvironmentType: SingleInstance\n"
        "  aws:ec2:vpc:\n"
        f"    VPCId: {vpc_id}\n"
        f"    Subnets: {subnets}\n"
        "    AssociatePublicIpAddress: true\n"
        "  aws:autoscaling:launchconfiguration:\n"
        f"    IamInstanceProfile: {ec2_profile_name}\n"
        "    InstanceType: t3.micro\n"
        "    DisableDefaultEC2SecurityGroup: true\n"
        f"    SecurityGroups: {sg_id}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("env.yaml", manifest)
        zf.writestr("index.html", f"<html><body>{name_prefix}</body></html>")
    return buf.getvalue()


def _create_eb_roles(ctx) -> tuple[str, str]:
    """The environments' service role and EC2 instance profile; each teardown runs after the
    environments are gone, as those teardowns are registered later."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-ebrole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    def trust(service: str) -> str:
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        })

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=trust("elasticbeanstalk.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    web_tier = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=trust("ec2.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn=web_tier)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=web_tier))

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))
    return svc_name, ec2_name


def _wait_version_processed(
    eb, app_name: str, label: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        versions = eb.describe_application_versions(
            ApplicationName=app_name, VersionLabels=[label]
        )["ApplicationVersions"]
        if versions:
            last = versions[0]["Status"]
            # Real AWS has been observed returning this field upper-cased
            # ("PROCESSED"/"FAILED") rather than the modeled title-case enum
            # ("Processed"/"Failed") -- compare case-insensitively.
            if last is not None and last.upper() in ("PROCESSED", "FAILED"):
                assert last.upper() == "PROCESSED", (
                    f"application version {label} failed processing (status={last})"
                )
                return
        time.sleep(interval_s)
    raise AssertionError(f"application version {label} never finished processing; last status={last}")


def _wait_for_envs_status(
    eb,
    names: list[str],
    target_statuses: set[str],
    timeout_s: float = 900.0,
    interval_s: float = 15.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=list(names), IncludeDeleted=False)
        found = {e["EnvironmentName"]: e for e in resp.get("Environments", [])}
        last = found
        if all(n in found and found[n]["Status"] in target_statuses for n in names):
            return found
        time.sleep(interval_s)
    raise AssertionError(f"environments {names} never all reached {target_statuses}; last={last}")


def _poll_until_absent(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        last = resp.get("Environments", [])
        if not last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never disappeared from DescribeEnvironments; last={last}")


def _pending(exc: ClientError) -> bool:
    """TerminateEnvironment's refusal of an environment whose creation or update is still running."""
    err = exc.response["Error"]
    return err["Code"] == "InvalidParameterValue" and "It is currently pending" in err.get("Message", "")


def _terminate_when_accepted(eb, env_name: str, timeout_s: float) -> None:
    """TerminateEnvironment, retried every 2 s while the tag update's deployment is still pending."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eb.terminate_environment(EnvironmentName=env_name)
            return
        except ClientError as exc:
            if not _pending(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _terminate_envs_and_wait(eb, env_names: list[str], teardown: dict) -> None:
    """Terminate every environment and poll every 2 s to the shared deadline until each is gone or
    Terminated, re-issuing TerminateEnvironment while one is refused as still pending; an already
    terminating or gone environment counts as accepted and anything else raises."""
    if not env_names:
        return
    deadline = _deadline(teardown)
    pending = list(env_names)
    while True:
        statuses = {
            e["EnvironmentName"]: e["Status"]
            for e in eb.describe_environments(EnvironmentNames=list(pending), IncludeDeleted=False).get(
                "Environments", [])
        } if pending else {}
        for name in list(pending):
            if statuses.get(name) in ("Terminating", "Terminated"):
                pending.remove(name)
                continue
            try:
                eb.terminate_environment(EnvironmentName=name)
                pending.remove(name)
            except ClientError as exc:
                err = exc.response["Error"]
                message = err.get("Message", "")
                if err["Code"] == "InvalidParameterValue" and message.startswith("Environment not found"):
                    pending.remove(name)
                    continue
                if not _pending(exc) or time.monotonic() >= deadline:
                    raise
        envs = eb.describe_environments(EnvironmentNames=list(env_names), IncludeDeleted=False).get(
            "Environments", [])
        live = {e["EnvironmentName"]: e["Status"] for e in envs if e["Status"] != "Terminated"}
        if not pending and not live:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"at the teardown deadline environments {live!r} are not terminated "
                f"(terminate not yet accepted for {pending!r})")
        time.sleep(2)


# One deadline shared by all of the check's teardowns, inside the suite's 900 s cleanup budget.
_TEARDOWN_S = 840.0


def _deadline(teardown: dict) -> float:
    """The run's teardown deadline, started by its first teardown."""
    return teardown.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _poll_composed(ctx, eb, app_name: str) -> dict[str, Any]:
    """The application's cmpa*/cmpb* environments, polled every 2 s until both are listed (300 s,
    capped by the check's remaining time); returns what was found last."""
    left = ctx.time_left()
    deadline = time.monotonic() + (300.0 if left is None else max(1.0, min(300.0, left - 5.0)))
    found: dict[str, Any] = {}
    while True:
        envs = eb.describe_environments(ApplicationName=app_name, IncludeDeleted=False).get("Environments", [])
        found = {e["EnvironmentName"]: e for e in envs if e["EnvironmentName"].startswith(("cmpa", "cmpb"))}
        if len(found) >= 2 or time.monotonic() >= deadline:
            return found
        time.sleep(2)


def _create_closed_security_group(ctx, vpc_id: str, teardown: dict) -> str:
    """A security group with no inbound rule, deleted once the environments' instances release it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eb-sg-")
    sg_id = ec2.create_security_group(GroupName=name, Description="EB instances, no inbound", VpcId=vpc_id)["GroupId"]

    def _delete() -> None:
        deadline = _deadline(teardown)
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_delete)
    return sg_id


def _delete_app(eb, app_name: str) -> None:
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
