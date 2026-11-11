"""environment-info-log-payload-preserved."""
from __future__ import annotations

import io
import json
import time
import urllib.request
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-info-log-payload-preserved"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]

_MARKER = "sim2real-tail-marker: \u4e16\u754c \U0001f600 caf\u00e9 \u00e9\u00e8"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """The tail log retrieved via RetrieveEnvironmentInfo reproduces a non-ASCII application
    log line byte-identical, with no truncation or mojibake."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    version_label = ctx.unique_name("sim2real-eb-ver-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{version_label}/app.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_build_marker_app_bundle(_MARKER))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    stack = _pick_solution_stack(ctx)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    instance_profile = _ensure_ec2_instance_profile(ctx)
    if instance_profile:
        option_settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    _create_env_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        VersionLabel=version_label,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=option_settings,
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))
    _wait_for_environment_status(ctx, env_name, "Ready", timeout_s=1200)

    found, last_seen = _poll_for_marker_in_tail(ctx, env_name, eb, _MARKER, attempts=6, per_attempt_timeout_s=90)
    assert found, (
        f"marker {_MARKER!r} never appeared byte-identical in the downloaded RetrieveEnvironmentInfo "
        f"tail bundle; last seen {len(last_seen)} bundle(s), first bytes of each: "
        f"{[s[:300] for s in last_seen]!r}"
    )


def _build_marker_app_bundle(marker: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            '{"name": "sim2real-marker-app", "version": "1.0.0", '
            '"scripts": {"start": "node app.js"}}\n',
        )
        zf.writestr(
            "app.js",
            "console.log(" + _js_string_literal(marker) + ");\n"
            "const http = require('http');\n"
            "http.createServer((req, res) => { res.end('ok'); })\n"
            "  .listen(process.env.PORT || 8080);\n",
        )
    return buf.getvalue()


def _js_string_literal(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace("'", "\\'")
    return "'" + escaped + "'"


def _ensure_ec2_instance_profile(ctx: Any) -> str | None:
    """Best-effort: create a per-run EC2 instance profile (with the EB web-tier managed
    policy) and register LIFO teardown, so the launched EC2 instance can actually boot
    and run the app -- a fresh sandbox account has no default
    ``aws-elasticbeanstalk-ec2-role`` for the API path (only the console auto-creates
    one). Degrades to None when IAM is unreachable, letting the service fall back to
    its own default."""
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        return None

    role_name = ctx.unique_name("sim2real-eb-ec2-role-")
    profile_name = ctx.unique_name("sim2real-eb-ec2-profile-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    try:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    except Exception as exc:  # noqa: BLE001 -- already-exists is fine
        if "EntityAlreadyExists" not in str(exc):
            return None
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    )
    try:
        iam.create_instance_profile(InstanceProfileName=profile_name)
    except Exception as exc:  # noqa: BLE001
        if "EntityAlreadyExists" not in str(exc):
            return None
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    return profile_name


def _create_env_with_retry(ctx: Any, eb: Any, **kwargs: Any) -> dict:
    """CreateEnvironment, retried over the refusal Elastic Beanstalk returns while the IAM
    principals just created are not yet visible to it; anything else re-raises."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else max(1.0, min(120.0, left - 5.0)))
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if time.monotonic() >= deadline or not (
                exc.response["Error"]["Code"] in ("InvalidParameterValue", "InsufficientPrivilegesException")
                and ("role" in msg or "instance profile" in msg or "permission" in msg)
            ):
                raise
            time.sleep(2)


def _terminate_env_and_wait(eb: Any, env_name: str, timeout_s: float = 600.0) -> None:
    """Teardown: terminate the environment and wait for Terminated, so its instance and Elastic IP
    are released; re-issued while EB refuses it mid-operation (invalid state, pending deployment).
    An environment already gone counts as terminated."""
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if envs[0]["Status"] != "Terminating":
            try:
                eb.terminate_environment(EnvironmentName=env_name)
            except ClientError as exc:
                msg = exc.response["Error"].get("Message", "")
                if "not found" in msg.lower():
                    return
                if not ("invalid state" in msg or "pending deployment" in msg) or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"environment {env_name} not terminated within {timeout_s:.0f}s")
        time.sleep(2)


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("account/region has no available Elastic Beanstalk solution stacks")
    for s in stacks:
        if "Amazon Linux 2023" in s and "Node.js" in s:
            return s
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_environment_status(ctx: Any, env_name: str, want_status: str, timeout_s: float = 900.0) -> None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if envs:
            last_status = envs[0]["Status"]
            if last_status == want_status:
                return
        time.sleep(2)
    raise AssertionError(f"environment {env_name} never reached status {want_status!r}, last seen {last_status!r}")


def _poll_for_marker_in_tail(
    ctx, env_name: str, eb: Any, marker: str, attempts: int, per_attempt_timeout_s: float
) -> tuple[bool, list[str]]:
    """RetrieveEnvironmentInfo(InfoType="tail")'s ``Message`` is a pre-signed S3 URL to the
    compiled log bundle, not the log text itself -- the bundle has to be downloaded and
    decoded to see what the instance actually wrote."""
    last_seen: list[str] = []
    for _ in range(attempts):
        eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")
        deadline = time.monotonic() + per_attempt_timeout_s
        while time.monotonic() < deadline:
            info = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")["EnvironmentInfo"]
            last_seen = []
            for item in info:
                url = item.get("Message", "")
                if not url:
                    continue
                target, route = ctx.endpoint_route(url)
                with urllib.request.urlopen(  # noqa: S310 -- AWS-issued presigned URL
                    urllib.request.Request(target, headers=route), timeout=30, context=_ssl_context(ctx.http_verify)
                ) as resp:
                    body = resp.read()
                text = body.decode("utf-8", errors="replace")
                last_seen.append(text[:2000])
                if marker in text:
                    return True, last_seen
            time.sleep(2)
    return False, last_seen


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
