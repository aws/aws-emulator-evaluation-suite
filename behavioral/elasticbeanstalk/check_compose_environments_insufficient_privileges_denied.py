"""compose-environments-insufficient-privileges-denied."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags

CHECK = "compose-environments-insufficient-privileges-denied"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("cap:c1", "cap:c4", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """ComposeEnvironments accepts a manifest that omits the required IamInstanceProfile, but the
    composed environment records an explicit launch-failure event and never reaches Ready: a
    missing instance profile must not yield a working environment."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-ebip-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)))

    stack = _pick_solution_stack(eb)
    env_name = ctx.unique_name("sim2real-ebip-env-")
    version_label = _create_manifest_version(ctx, eb, s3, app_name, env_name, stack)
    _wait_for_version_processed(eb, app_name, version_label)

    resp = eb.compose_environments(ApplicationName=app_name, VersionLabels=[version_label])
    # Materialization is asynchronous and takes from under a minute to several minutes on AWS.
    left = ctx.time_left()
    deadline_s = 300.0 if left is None else max(1.0, min(300.0, left - 5.0))
    created_env_name = _resolve_composed_environment_name(eb, app_name, env_name, resp, timeout_s=deadline_s, interval_s=2.0)
    if created_env_name is None:
        raise AssertionError(
            "ComposeEnvironments did not materialize the composed environment within 300s of the "
            f"call (or the run's remaining time) for application {app_name!r}"
        )
    ctx.on_cleanup(lambda: _terminate_environment(eb, created_env_name))
    _tag_environment(eb, app_name, created_env_name)

    outcome = _wait_for_instance_profile_rejection(eb, created_env_name, timeout_s=110.0)
    assert outcome["seen_rejection"], (
        f"expected an instance-profile-missing failure for environment {created_env_name}, "
        f"but observed status={outcome['status']!r} health={outcome['health']!r} "
        f"events={outcome['sample_messages']!r}"
    )
    assert outcome["status"] != "Ready", (
        f"environment {created_env_name} reached Ready despite having no IamInstanceProfile "
        f"(status={outcome['status']!r})"
    )

    # (c) positive control: the API remains usable for a normal, unrelated call on this account
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert apps and apps[0]["ApplicationName"] == app_name, (
        f"expected DescribeApplications to still return {app_name!r} after the rejection, got {apps!r}"
    )


# ===== helpers =====

def _safe(fn) -> None:
    """Run one teardown call; only a not-found answer means already gone, anything else raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", "")):
            raise


def _terminate_environment(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Terminate and wait for Terminated, re-issuing the call while a still-launching environment
    answers InvalidParameterValue ("invalid state"); any other error raises."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if envs[0]["Status"] != "Terminating":
            try:
                eb.terminate_environment(EnvironmentName=env_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidParameterValue":
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s}s")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s and "2023" not in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _create_manifest_version(ctx, eb, s3, app_name: str, env_name: str, stack: str) -> str:
    """Upload a source bundle whose env.yaml manifest deliberately supplies no IamInstanceProfile."""
    manifest = (
        "AWSConfigurationTemplateVersion: 1.1.0.0\n"
        f"SolutionStack: {stack}\n"
        f"EnvironmentName: {env_name}\n"
    )
    bucket = eb.create_storage_location()["S3Bucket"]
    key = ctx.unique_name("sim2real-ebip-bundle-") + ".zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("env.yaml", manifest)
    buf.seek(0)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.read())

    version_label = ctx.unique_name("sim2real-ebip-ver-")
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        Process=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    return version_label


def _wait_for_version_processed(eb, app_name: str, version_label: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        versions = eb.describe_application_versions(
            ApplicationName=app_name, VersionLabels=[version_label]
        )["ApplicationVersions"]
        last_status = versions[0]["Status"] if versions else None
        if last_status in ("PROCESSED", "FAILED"):
            assert last_status == "PROCESSED", (
                f"application version processing unexpectedly ended in status {last_status!r}"
            )
            return
        time.sleep(interval_s)
    raise AssertionError(f"application version never finished processing (last status: {last_status})")


def _tag_environment(eb, app_name: str, env_name: str) -> None:
    """Tag the composed environment like the check's other resources (ComposeEnvironments takes
    no Tags parameter). An environment that is not Ready refuses tag updates; it stays untagged."""
    from botocore.exceptions import ClientError

    envs = eb.describe_environments(ApplicationName=app_name, EnvironmentNames=[env_name]).get("Environments", [])
    arn = envs[0].get("EnvironmentArn") if envs else None
    if arn:
        try:
            eb.update_tags_for_resource(ResourceArn=arn, TagsToAdd=[{"Key": "sim2real", "Value": CHECK}])
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "InvalidParameterValue" and "Must be Ready" in err.get("Message", "")):
                raise


def _resolve_composed_environment_name(eb, app_name: str, env_name: str, compose_response: dict, timeout_s: float = 60.0, interval_s: float = 5.0):
    """ComposeEnvironments may return the composed environment synchronously in its response,
    or only make it visible via DescribeEnvironments a moment later; check both. Returns None
    (rather than raising) if it never becomes visible within timeout_s.
    """
    envs_from_response = compose_response.get("Environments", [])
    if envs_from_response:
        return envs_from_response[0]["EnvironmentName"]

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(
            ApplicationName=app_name, IncludeDeleted=False
        ).get("Environments", [])
        if envs:
            return envs[0]["EnvironmentName"]
        time.sleep(interval_s)
    return None


def _wait_for_instance_profile_rejection(eb, env_name: str, timeout_s: float = 110.0, interval_s: float = 8.0) -> dict:
    """Poll DescribeEvents/DescribeEnvironments until either the missing-instance-profile
    rejection is observed, the environment reaches a terminal non-Ready state, or the timeout
    elapses.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    health = None
    sample_messages: list[str] = []
    seen = False
    while time.monotonic() < deadline:
        events = eb.describe_events(EnvironmentName=env_name, MaxRecords=50).get("Events", [])
        for ev in events:
            msg = ev.get("Message", "")
            if "instance profile" in msg.lower() or "failed to launch environment" in msg.lower():
                seen = True
            if len(sample_messages) < 8:
                sample_messages.append(msg)
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            status = envs[0].get("Status")
            health = envs[0].get("Health")
        if seen or status in ("Terminated", "Terminating"):
            break
        time.sleep(interval_s)
    return {
        "seen_rejection": seen,
        "status": status,
        "health": health,
        "sample_messages": sample_messages,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

