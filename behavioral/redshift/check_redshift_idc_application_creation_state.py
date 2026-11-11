"""redshift-idc-application-creation-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-idc-application-creation-state"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateRedshiftIdcApplication becomes immediately describable via
    DescribeRedshiftIdcApplications, and DeleteRedshiftIdcApplication removes it
    so the same describe call subsequently 404s."""
    idc_instance_arn = _find_or_create_idc_instance(ctx)
    role_arn = _create_idc_role(ctx)

    redshift = ctx.client("redshift")
    app_name = ctx.unique_name("sim2real-rsidc-").lower()
    display_name = ctx.unique_name("Sim2Real-RSIDC-")

    created = _create_application_with_retry(
        redshift, idc_instance_arn, app_name, display_name, role_arn
    )["RedshiftIdcApplication"]
    app_arn = created["RedshiftIdcApplicationArn"]
    assert created["RedshiftIdcApplicationName"] == app_name, (
        f"expected name {app_name!r}, got {created['RedshiftIdcApplicationName']!r}"
    )
    assert created["IdcDisplayName"] == display_name, (
        f"expected display name {display_name!r}, got {created['IdcDisplayName']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_app(redshift, app_arn))

    described = redshift.describe_redshift_idc_applications(
        RedshiftIdcApplicationArn=app_arn
    )["RedshiftIdcApplications"]
    assert len(described) == 1, f"expected exactly the created application, got {described!r}"
    assert described[0]["RedshiftIdcApplicationArn"] == app_arn
    assert described[0]["RedshiftIdcApplicationName"] == app_name

    redshift.delete_redshift_idc_application(RedshiftIdcApplicationArn=app_arn)
    not_exists = f"The RedshiftIdcApplication with the ARN {app_arn} wasn't found."

    code, message = _error(
        lambda: redshift.describe_redshift_idc_applications(
            RedshiftIdcApplicationArn=app_arn
        )
    )
    assert code == "RedshiftIdcApplicationNotExists", (
        f"expected RedshiftIdcApplicationNotExists reading the deleted application, got {code!r}"
    )
    assert message == not_exists, (
        f"reading the deleted application: expected message {not_exists!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _find_or_create_idc_instance(ctx) -> str:
    """Resolve an IAM Identity Center instance ARN, creating one if the account has
    none. sso-admin:CreateInstance provisions a real instance for any standalone or
    member account (it is rejected only in the org management account, or when one
    already exists), so this is a create-or-adopt prerequisite, not an external one.
    The instance is an account-global singleton -- one per account, across every
    region -- shared with other checks in this suite, so a created instance is
    deliberately left in place rather than torn down in ctx.on_cleanup."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        try:
            instance_arn = sso.create_instance(Name="sim2real-behavioral-idc")["InstanceArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ConflictException":
                instances = sso.list_instances().get("Instances", [])
                if instances:
                    instance_arn = instances[0]["InstanceArn"]
                else:
                    raise AssertionError(
                        f"CreateInstance said {code} (already exists) but list_instances "
                        "still returns none"
                    ) from exc
            else:
                raise AssertionError(
                    f"could not create or adopt an IAM Identity Center instance ({code}); "
                    "CreateRedshiftIdcApplication requires one"
                ) from exc
    return _wait_for_instance_active(sso, instance_arn)


def _wait_for_instance_active(sso, instance_arn: str, timeout_s=120, interval_s=3) -> str:
    """A freshly created (or freshly adopted, mid-transition) instance reports
    CREATE_IN_PROGRESS/DELETE_IN_PROGRESS before ACTIVE; CreateRedshiftIdcApplication
    rejects anything but ACTIVE with InvalidParameterValue, so this is a bounded
    poll, not a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if last_status == "ACTIVE":
            return instance_arn
        if last_status == "CREATE_FAILED":
            raise AssertionError(f"IAM Identity Center instance {instance_arn} CREATE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(
        f"IAM Identity Center instance {instance_arn} did not reach ACTIVE within "
        f"{timeout_s}s; last status {last_status!r}"
    )


def _create_idc_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rsidc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral fidelity check role for Redshift IDC application",
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role["Arn"]


def _create_application_with_retry(redshift, idc_instance_arn, app_name, display_name, role_arn, attempts=6):
    """Freshly created IAM roles take a few seconds to propagate; retry on the
    dependent-service errors that eventual consistency can trigger before treating
    the failure as terminal."""
    last_code = None
    for attempt in range(attempts):
        try:
            return redshift.create_redshift_idc_application(
                IdcInstanceArn=idc_instance_arn,
                RedshiftIdcApplicationName=app_name,
                IdcDisplayName=display_name,
                IamRoleArn=role_arn,
                Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code in ("DependentServiceAccessDenied", "DependentServiceUnavailableFault"):
                if attempt == attempts - 1:
                    raise AssertionError(
                        f"CreateRedshiftIdcApplication kept failing with {last_code} even "
                        "after retrying for IAM propagation"
                    ) from exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"unreachable: last error code was {last_code}")


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_app(redshift, app_arn: str) -> None:
    try:
        redshift.delete_redshift_idc_application(RedshiftIdcApplicationArn=app_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RedshiftIdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
