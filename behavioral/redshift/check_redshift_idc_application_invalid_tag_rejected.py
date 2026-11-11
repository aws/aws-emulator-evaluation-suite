"""redshift-idc-application-invalid-tag-rejected."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-idc-application-invalid-tag-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateRedshiftIdcApplication with a tag using the reserved 'aws:' key prefix
    is rejected with InvalidParameterValue ("Caller is an end user and not allowed to
    mutate system tags") rather than accepted and then silently dropped/sanitized."""
    idc_instance_arn = _require_idc_instance(ctx)
    redshift = ctx.client("redshift")
    role_arn = _create_idc_role(ctx)
    app_name = _idc_name(ctx, "sim2real-idctag-")

    code, message = _error(
        lambda: redshift.create_redshift_idc_application(
            IdcInstanceArn=idc_instance_arn,
            RedshiftIdcApplicationName=app_name,
            IdcDisplayName="sim2real-idctag-display",
            IamRoleArn=role_arn,
            Tags=[{"Key": "aws:reserved-key", "Value": "should-be-rejected"}],
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a create carrying an aws:-prefixed tag key, got {code}"
    )
    expected_message = "Caller is an end user and not allowed to mutate system tags"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no application was created under this name.
    existing = [
        a
        for a in redshift.describe_redshift_idc_applications().get(
            "RedshiftIdcApplications", []
        )
        if a["RedshiftIdcApplicationName"] == app_name
    ]
    assert existing == [], (
        f"expected no application named {app_name!r} after the rejected create, found {existing!r}"
    )

    # Positive control: the same call without the reserved-prefix tag succeeds.
    created = redshift.create_redshift_idc_application(
        IdcInstanceArn=idc_instance_arn,
        RedshiftIdcApplicationName=app_name,
        IdcDisplayName="sim2real-idctag-display",
        IamRoleArn=role_arn,
        Tags=[{"Key": "sim2real-check", "Value": "true"}],
    )["RedshiftIdcApplication"]
    app_arn = created["RedshiftIdcApplicationArn"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: redshift.delete_redshift_idc_application(
                RedshiftIdcApplicationArn=app_arn
            )
        )
    )

    # Terminal read: independent of the create call, at the destination. Confirms the
    # application exists under this ARN AND that the non-reserved tag was actually
    # applied rather than silently dropped -- the point of the positive control.
    described = redshift.describe_redshift_idc_applications(
        RedshiftIdcApplicationArn=app_arn
    ).get("RedshiftIdcApplications", [])
    assert len(described) == 1, (
        f"expected exactly one application at {app_arn}, describe returned {described!r}"
    )
    app = described[0]
    assert app["RedshiftIdcApplicationName"] == app_name, (
        f"expected {app_name!r} at {app_arn}, describe returned "
        f"{app['RedshiftIdcApplicationName']!r}"
    )
    applied_tags = {t["Key"]: t["Value"] for t in app.get("Tags", [])}
    assert applied_tags.get("sim2real-check") == "true", (
        "expected the non-reserved tag sim2real-check=true to have been applied, "
        f"describe returned tags {applied_tags!r}"
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


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "RedshiftIdcApplicationNotExists"):
            raise


def _require_idc_instance(ctx) -> str:
    sso = ctx.client("sso-admin")
    try:
        instances = sso.list_instances().get("Instances", [])
    except ClientError as err:
        raise AssertionError(
            "unable to list IAM Identity Center instances "
            f"({err.response['Error']['Code']}); cannot create a "
            "RedshiftIdcApplication without a real instance ARN"
        ) from err
    if not instances:
        # Not a wall: `sso-admin:CreateInstance` provisions a STANDALONE (non-Organizations)
        # instance, so the prerequisite is satisfiable in-check -- an account may simply not have
        # an instance yet. Only one is allowed per account, so an instance created here is
        # deliberately left in place.
        import time

        sso.create_instance()
        deadline = time.time() + 120
        while time.time() < deadline:
            instances = sso.list_instances().get("Instances", [])
            if (
                instances
                and sso.describe_instance(InstanceArn=instances[0]["InstanceArn"])["Status"]
                == "ACTIVE"
            ):
                break
            time.sleep(3)
        assert instances, (
            "created an IAM Identity Center instance but it never became ACTIVE/listable"
        )
    return instances[0]["InstanceArn"]


def _idc_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    cleaned = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "r" + cleaned
    return cleaned


def _create_idc_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-idctag-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "redshift.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
