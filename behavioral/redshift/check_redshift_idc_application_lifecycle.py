"""redshift-idc-application-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-idc-application-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A created Redshift IdC application is visible via DescribeRedshiftIdcApplications, a
    duplicate-name create is rejected as a conflict without mutating the original, and delete
    frees the name and ends in a not-found read."""
    idc_instance_arn = _require_or_create_idc_instance(ctx)
    role_arn = _create_service_role(ctx, "redshift.amazonaws.com")

    redshift = ctx.client("redshift")
    app_name = ctx.unique_name("sim2real-idcapp-")

    created = _retry_transient(
        lambda: redshift.create_redshift_idc_application(
            IdcInstanceArn=idc_instance_arn,
            RedshiftIdcApplicationName=app_name,
            IdcDisplayName="sim2real-behavioral-test-app",
            IamRoleArn=role_arn,
        )
    )
    app = created["RedshiftIdcApplication"]
    app_arn = app["RedshiftIdcApplicationArn"]
    ctx.on_cleanup(lambda: _delete_idc_application_ignore_missing(ctx, app_arn))
    assert app["RedshiftIdcApplicationName"] == app_name
    assert app["IdcInstanceArn"] == idc_instance_arn

    described = redshift.describe_redshift_idc_applications(RedshiftIdcApplicationArn=app_arn)
    apps = described["RedshiftIdcApplications"]
    assert len(apps) == 1 and apps[0]["RedshiftIdcApplicationArn"] == app_arn

    # boundary: re-using an already-registered application name must be rejected, not
    # silently accepted/overwritten
    dup_code, dup_message = _error(
        lambda: redshift.create_redshift_idc_application(
            IdcInstanceArn=idc_instance_arn,
            RedshiftIdcApplicationName=app_name,
            IdcDisplayName="sim2real-behavioral-test-app-duplicate",
            IamRoleArn=role_arn,
        )
    )
    assert dup_code == "RedshiftIdcApplicationAlreadyExists", (
        f"expected RedshiftIdcApplicationAlreadyExists for duplicate name, got {dup_code}"
    )
    expected_dup = (
        f"You already have a RedshiftIdcApplication with the name {app_name}. "
        "Use a different name."
    )
    assert dup_message == expected_dup, (
        f"duplicate create: expected message {expected_dup!r}, got {dup_message!r}"
    )

    # the rejected duplicate must not have mutated the original it collided with
    unaffected = redshift.describe_redshift_idc_applications(RedshiftIdcApplicationArn=app_arn)[
        "RedshiftIdcApplications"
    ][0]
    assert unaffected["IdcDisplayName"] == "sim2real-behavioral-test-app", (
        "rejected duplicate create must not mutate the existing application, got "
        f"IdcDisplayName={unaffected['IdcDisplayName']!r}"
    )

    redshift.delete_redshift_idc_application(RedshiftIdcApplicationArn=app_arn)

    final_code, final_message = _error(
        lambda: redshift.describe_redshift_idc_applications(RedshiftIdcApplicationArn=app_arn)
    )
    assert final_code == "RedshiftIdcApplicationNotExists", (
        f"expected RedshiftIdcApplicationNotExists after delete, got {final_code}"
    )
    assert final_message == f"The RedshiftIdcApplication with the ARN {app_arn} wasn't found.", (
        f"describe after delete: expected the not-exists message, got {final_message!r}"
    )

    # restore: deleting the original frees the name, so the identical create now succeeds
    recreated = _retry_transient(
        lambda: redshift.create_redshift_idc_application(
            IdcInstanceArn=idc_instance_arn,
            RedshiftIdcApplicationName=app_name,
            IdcDisplayName="sim2real-behavioral-test-app-restored",
            IamRoleArn=role_arn,
        )
    )
    recreated_arn = recreated["RedshiftIdcApplication"]["RedshiftIdcApplicationArn"]
    ctx.on_cleanup(lambda: _delete_idc_application_ignore_missing(ctx, recreated_arn))
    assert recreated["RedshiftIdcApplication"]["RedshiftIdcApplicationName"] == app_name


# ===== helpers =====


def _require_or_create_idc_instance(ctx):
    """Adopt an existing IAM Identity Center instance, or create one for this
    account. A fresh account with no organization-wide instance still exposes
    CreateInstance for a local (per-account) instance, so absence is a
    prerequisite to satisfy, not a permanent block."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]

    created = sso.create_instance(
        Name=ctx.unique_name("sim2real-idc-"),
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _delete_idc_instance_ignore_missing(ctx, instance_arn))
    _wait_for_instance_active(sso, instance_arn)
    return instance_arn


def _wait_for_instance_active(sso, instance_arn, attempts=24, delay_s=5):
    """CreateInstance is asynchronous; bounded poll for the transition out of
    CREATE_IN_PROGRESS, since nothing else in this account will move it."""
    for attempt in range(attempts):
        described = sso.describe_instance(InstanceArn=instance_arn)
        status = described["Status"]
        if status == "ACTIVE":
            return
        if status == "CREATE_FAILED":
            raise AssertionError(
                f"IAM Identity Center instance creation failed: {described.get('StatusReason')}"
            )
        if attempt == attempts - 1:
            raise AssertionError(
                f"IAM Identity Center instance {instance_arn} did not reach ACTIVE within "
                f"{attempts * delay_s}s, last status={status}"
            )
        time.sleep(delay_s)


def _delete_idc_instance_ignore_missing(ctx, instance_arn, timeout_s=120):
    """Delete the instance; a conflict while its applications are still being removed is retried
    to a deadline. DeleteInstance documents no not-found code, so any other error counts as done
    only when ListInstances no longer shows the instance, and raises otherwise."""
    from botocore.exceptions import ClientError

    sso = ctx.client("sso-admin")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sso.delete_instance(InstanceArn=instance_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "ConflictException":
                if not _idc_instance_listed(sso, instance_arn):
                    return
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _idc_instance_listed(sso, instance_arn):
    """True when ListInstances (all pages) still shows instance_arn."""
    kwargs = {}
    while True:
        page = sso.list_instances(**kwargs)
        if any(i.get("InstanceArn") == instance_arn for i in page.get("Instances", [])):
            return True
        if not page.get("NextToken"):
            return False
        kwargs["NextToken"] = page["NextToken"]


def _create_service_role(ctx, principal):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-idcrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": [principal, "sso.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral test throwaway role",
    )["Role"]
    role_arn = role["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_transient(fn, attempts=6, delay_s=5):
    from botocore.exceptions import ClientError

    transient = {
        "InvalidParameterValue",
        "DependentServiceAccessDenied",
        "DependentServiceAccessDeniedFault",
        "DependentServiceUnavailableFault",
    }
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in transient or attempt == attempts - 1:
                raise
            time.sleep(delay_s)


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_idc_application_ignore_missing(ctx, app_arn):
    from botocore.exceptions import ClientError

    redshift = ctx.client("redshift")
    try:
        redshift.delete_redshift_idc_application(RedshiftIdcApplicationArn=app_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RedshiftIdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
