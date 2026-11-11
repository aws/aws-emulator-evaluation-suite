"""rebuild-terminated-environment-version-deleted-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "rebuild-terminated-environment-version-deleted-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebuildEnvironment on a Terminated environment is rejected with InvalidParameterValue whether
    or not its deployed version still exists, and never resurrects it; a live rebuild succeeds."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    version_label = "v1"

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: _delete_app(eb, app_name))

    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{app_name}/{version_label}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_python_app_zip())

    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
    )

    profile, svc_role = _eb_iam(ctx)
    stack = _pick_solution_stack(eb)
    _create_env_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        VersionLabel=version_label,
        SolutionStackName=stack,
        OptionSettings=_base_options(profile, svc_role),
    )
    ctx.on_cleanup(lambda: _terminate_env(eb, env_name, TerminateResources=True))
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900.0)

    # Positive control: RebuildEnvironment itself works, on a live environment. Without this,
    # "rejected once Terminated" would be indistinguishable from "RebuildEnvironment always fails
    # in this account".
    eb.rebuild_environment(EnvironmentName=env_name)
    _wait_for_env_status(eb, env_name, {"Updating", "Terminating", "Launching"}, timeout_s=180.0, interval_s=2.0)
    ready = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900.0)
    assert ready["Status"] == "Ready", f"expected Ready after rebuild-while-live, got {ready['Status']}"

    # Break: terminate for real, with the deployed version still present.
    eb.terminate_environment(EnvironmentName=env_name, TerminateResources=True)
    _wait_for_env_status(eb, env_name, {"Terminated"}, timeout_s=600.0)

    # Rejected even though the deployed version still exists, unlike what the developer guide's
    # "Rebuilding a terminated environment" section implies.
    expected_message = f"No Environment found for EnvironmentName = '{env_name}'."
    code_a, message_a = _error_code_and_message(lambda: eb.rebuild_environment(EnvironmentName=env_name))
    assert code_a == "InvalidParameterValue", (
        f"expected InvalidParameterValue rebuilding a Terminated env with its version present, got {code_a}"
    )
    assert message_a == expected_message, (
        f"expected message {expected_message!r}, got {message_a!r}"
    )

    # Effect absent: the rejected rebuild did not resurrect the environment.
    envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
    assert len(envs) == 1, f"expected exactly 1 environment named {env_name}, got {len(envs)}"
    assert envs[0]["Status"] == "Terminated", (
        f"expected Terminated after the version-present rejection, got {envs[0]['Status']}"
    )

    _delete_version_with_retry(eb, app_name, version_label, timeout_s=120.0)

    # Independent read: the version is actually gone, not just reported deleted.
    remaining = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[version_label]
    )["ApplicationVersions"]
    assert remaining == [], f"expected version {version_label} gone after delete, still listed: {remaining}"

    # With the version also gone the identical call is rejected the same way.
    code_b, message_b = _error_code_and_message(lambda: eb.rebuild_environment(EnvironmentName=env_name))
    assert code_b == code_a, (
        f"expected the version-deleted rejection to match the version-present one ({code_a}), got {code_b}"
    )
    assert message_b == expected_message, (
        f"expected message {expected_message!r}, got {message_b!r}"
    )

    # Effect absent, again: still no resurrection.
    envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
    assert len(envs) == 1, f"expected exactly 1 environment named {env_name}, got {len(envs)}"
    assert envs[0]["Status"] == "Terminated", (
        f"expected Terminated after the version-deleted rejection, got {envs[0]['Status']}"
    )


def _env_gone(msg: str) -> bool:
    """TerminateEnvironment's answers for an environment that does not exist."""
    return "No Environment found" in msg or "Environment not found with Name" in msg


def _terminate_env(eb, env_name, **kwargs) -> None:
    """TerminateEnvironment, retried every 2 s while the environment is mid-operation ("invalid
    state"); a not-found message means it is already gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 300
    while True:
        try:
            eb.terminate_environment(EnvironmentName=env_name, **kwargs)
            return
        except ClientError as exc:
            code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValue" and _env_gone(msg):
                return
            if code != "InvalidParameterValue" or "invalid state" not in msg or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_app(eb, app_name) -> None:
    """DeleteApplication (forcing its environments), retried every 2 s while an operation is in
    progress; "No Application named" means it is already gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 300
    while True:
        try:
            eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValue" and "No Application named" in exc.response["Error"].get("Message", ""):
                return
            if code != "OperationInProgressFailure" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected the call to be rejected, but it succeeded")
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")


def _eb_iam(ctx):
    """Create the instance profile and service role CreateEnvironment needs, with LIFO teardown.

    Only the console creates EB's default roles; returns (None, None) when IAM is unreachable."""
    iam = ctx.client("iam")
    try:
        iam.list_roles(MaxItems=1)
    except Exception:  # noqa: BLE001 -- no IAM at all: let EB apply its defaults
        return None, None

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": "eb-rebuild-terminated-version-deleted"}])
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policies:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-svc-role-")
    profile = ctx.unique_name("sim2real-eb-profile-")
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
    # IAM exposes no readiness signal for cross-service use of a new role; the bounded
    # CreateEnvironment retry covers its propagation.
    return profile, svc_role


def _base_options(profile, service_role):
    opts = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    if profile:
        opts.append({"Namespace": "aws:autoscaling:launchconfiguration",
                     "OptionName": "IamInstanceProfile", "Value": profile})
    if service_role:
        opts += [
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role},
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system",
             "OptionName": "SystemType", "Value": "enhanced"},
        ]
    return opts


def _create_env_with_retry(ctx, eb, **kwargs):
    """CreateEnvironment with a bounded retry over the IAM-propagation refusal."""
    left = ctx.time_left()
    deadline = time.monotonic() + (300 if left is None else min(300, max(0.0, left - 5)))
    while True:
        try:
            eb.create_environment(**kwargs)
            return
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if time.monotonic() >= deadline or not (
                    "not have permission" in msg or "cannot be assumed" in msg
                    or ("InvalidParameterValue" in msg and "role" in msg.lower())):
                raise
            time.sleep(2)


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    for s in stacks:
        if "Amazon Linux" in s and "Python" in s:
            return s
    return stacks[0]


def _minimal_python_app_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "application.py",
            "def application(environ, start_response):\n"
            "    start_response('200 OK', [('Content-Type', 'text/plain')])\n"
            "    return [b'ok']\n",
        )
    return buf.getvalue()


def _wait_for_env_status(eb, env_name: str, statuses: set, timeout_s: float, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"environment {env_name} did not reach {statuses} within {timeout_s}s "
        f"(last status={last['Status'] if last else None})"
    )


def _delete_version_with_retry(eb, app_name: str, version_label: str, timeout_s: float, interval_s: float = 2.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            eb.delete_application_version(
                ApplicationName=app_name, VersionLabel=version_label, DeleteSourceBundle=True
            )
            return
        except ClientError as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"could not delete application version {version_label}: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
