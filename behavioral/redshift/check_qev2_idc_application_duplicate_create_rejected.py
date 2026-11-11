"""qev2-idc-application-duplicate-create-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "qev2-idc-application-duplicate-create-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """While one Qev2 IdC application exists, a second create with the same or another name is
    rejected with Qev2IdcApplicationAlreadyExists "You already have a Qev2IdcApplication.", and the
    other name succeeds once the first is deleted."""
    idc_instance_arn = _ensure_idc_instance(ctx, ctx.client("sso-admin"))
    redshift = ctx.client("redshift")
    app_name = _qev2_name(ctx, "sim2real-qev2-dup-")

    created = redshift.create_qev2_idc_application(
        IdcInstanceArn=idc_instance_arn,
        Qev2IdcApplicationName=app_name,
        IdcDisplayName="sim2real-qev2-display",
    )["Qev2IdcApplication"]
    app_arn = created["Qev2IdcApplicationArn"]
    ctx.on_cleanup(lambda: _delete_qev2_app(redshift, app_arn))
    assert created["Qev2IdcApplicationName"] == app_name

    code, message = _error(
        lambda: redshift.create_qev2_idc_application(
            IdcInstanceArn=idc_instance_arn,
            Qev2IdcApplicationName=app_name,
            IdcDisplayName="sim2real-qev2-display-dup-attempt",
        )
    )
    assert code == "Qev2IdcApplicationAlreadyExists", code
    assert message == "You already have a Qev2IdcApplication.", (
        f"unexpected Qev2IdcApplicationAlreadyExists message {message!r}"
    )

    # Effect absent: the rejected duplicate must not have changed the display name.
    current = redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=app_arn)[
        "Qev2IdcApplications"
    ][0]
    assert current["IdcDisplayName"] == "sim2real-qev2-display"

    # The refusal is about the existing application, not the name: a fresh name is refused too.
    other_name = _qev2_name(ctx, "sim2real-qev2-ctrl-")
    other_code, other_message = _error(
        lambda: redshift.create_qev2_idc_application(
            IdcInstanceArn=idc_instance_arn,
            Qev2IdcApplicationName=other_name,
            IdcDisplayName="sim2real-qev2-ctrl-display",
        )
    )
    assert other_code == "Qev2IdcApplicationAlreadyExists", other_code
    assert other_message == "You already have a Qev2IdcApplication.", (
        f"unexpected Qev2IdcApplicationAlreadyExists message {other_message!r}"
    )

    # Positive control: once the first application is deleted, the fresh name succeeds.
    redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
    control = redshift.create_qev2_idc_application(
        IdcInstanceArn=idc_instance_arn,
        Qev2IdcApplicationName=other_name,
        IdcDisplayName="sim2real-qev2-ctrl-display",
    )["Qev2IdcApplication"]
    ctx.on_cleanup(lambda: _delete_qev2_app(redshift, control["Qev2IdcApplicationArn"]))
    assert control["Qev2IdcApplicationName"] == other_name


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_idc_instance(ctx, sso_admin) -> str:
    """Create-or-adopt the account's IAM Identity Center instance.

    ``sso-admin:CreateInstance`` self-provisions a standalone (non-organization)
    instance, so an absent instance is a prerequisite this check can satisfy itself
    rather than an external one. The instance is an account-global singleton left
    in place, never torn down by this check's cleanup.

    A freshly created instance is not immediately usable: real AWS answers
    CreateQev2IdcApplication with InvalidParameterValue ("... is not in 'ACTIVE'
    state") while the instance is still CREATE_IN_PROGRESS, so callers must wait
    for ACTIVE via an independent DescribeInstance poll rather than assuming
    CreateInstance's own response means ready.
    """
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        try:
            created = sso_admin.create_instance(
                Name=ctx.unique_name("sim2real-idc-"),
                Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
            )
        except ClientError as exc:
            error = exc.response["Error"]
            raise AssertionError(
                "no AWS IAM Identity Center instance is enabled in this account, and "
                f"sso-admin:CreateInstance was refused with {error['Code']}: {error.get('Message')}"
            ) from exc
        instance_arn = created["InstanceArn"]

    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        described = sso_admin.describe_instance(InstanceArn=instance_arn)
        status = described["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise AssertionError(
                f"IAM Identity Center instance {instance_arn} reached terminal status "
                f"{status!r} instead of ACTIVE: {described.get('StatusReason')}"
            )
        time.sleep(5)
    raise AssertionError(
        f"IAM Identity Center instance {instance_arn} did not reach ACTIVE within 120s "
        f"(last status: {status!r})"
    )

def _qev2_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    cleaned = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "q" + cleaned
    return cleaned


def _delete_qev2_app(redshift, arn: str) -> None:
    try:
        redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "Qev2IdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
