"""qev2-idc-application-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "qev2-idc-application-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]

_NOT_EXISTS_MESSAGE = "The Qev2IdcApplication you specified doesn't exist."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateQev2IdcApplication -> describable -> ModifyQev2IdcApplication updates
    the display name (verified via describe) -> DeleteQev2IdcApplication removes
    it (subsequent describe 404s)."""
    sso_admin = ctx.client("sso-admin")
    idc_instance_arn = _ensure_idc_instance(ctx, sso_admin)

    redshift = ctx.client("redshift")
    app_name = ctx.unique_name("sim2real-qev2-")
    display_name = ctx.unique_name("Sim2Real-QEV2-")

    created = redshift.create_qev2_idc_application(
        IdcInstanceArn=idc_instance_arn,
        Qev2IdcApplicationName=app_name,
        IdcDisplayName=display_name,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )["Qev2IdcApplication"]
    app_arn = created["Qev2IdcApplicationArn"]
    assert created["Qev2IdcApplicationName"] == app_name, (
        f"expected create to echo back the requested name {app_name!r}, got {created['Qev2IdcApplicationName']!r}"
    )
    assert created["IdcDisplayName"] == display_name, (
        f"expected create to echo back the requested display name {display_name!r}, got {created['IdcDisplayName']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_app(redshift, app_arn))

    described = redshift.describe_qev2_idc_applications(
        Qev2IdcApplicationArn=app_arn
    )["Qev2IdcApplications"]
    assert len(described) == 1, f"expected exactly one described application for {app_arn}, got {described}"
    assert described[0]["IdcDisplayName"] == display_name, (
        f"expected describe to reflect display name {display_name!r}, got {described[0]['IdcDisplayName']!r}"
    )

    new_display_name = ctx.unique_name("Sim2Real-QEV2-Renamed-")
    redshift.modify_qev2_idc_application(
        Qev2IdcApplicationArn=app_arn, IdcDisplayName=new_display_name
    )

    described_after_modify = redshift.describe_qev2_idc_applications(
        Qev2IdcApplicationArn=app_arn
    )["Qev2IdcApplications"]
    assert len(described_after_modify) == 1, (
        f"expected exactly one described application for {app_arn} after modify, got {described_after_modify}"
    )
    assert described_after_modify[0]["IdcDisplayName"] == new_display_name, (
        f"expected the independent describe to reflect the modified display name {new_display_name!r}, "
        f"got {described_after_modify[0]['IdcDisplayName']!r}"
    )
    assert described_after_modify[0]["Qev2IdcApplicationArn"] == app_arn, (
        f"expected the describe to keep the same ARN {app_arn!r}, got {described_after_modify[0]['Qev2IdcApplicationArn']!r}"
    )

    redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)

    code, message = _error(
        lambda: redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=app_arn)
    )
    assert code == "Qev2IdcApplicationNotExists", (
        f"expected an independent describe after delete to fail with Qev2IdcApplicationNotExists, got {code!r}"
    )
    assert message == _NOT_EXISTS_MESSAGE, f"unexpected Qev2IdcApplicationNotExists message {message!r}"

    mutate_code, mutate_message = _error(
        lambda: redshift.modify_qev2_idc_application(
            Qev2IdcApplicationArn=app_arn, IdcDisplayName="post-delete-should-fail"
        )
    )
    assert mutate_code == "Qev2IdcApplicationNotExists", (
        f"expected a mutation against the deleted application {app_arn} to also fail with "
        f"Qev2IdcApplicationNotExists, got {mutate_code!r}"
    )
    assert mutate_message == (
        "The Qev2IdcApplication you specified doesn't exist or the status isn't Completed."
    ), (
        f"unexpected Qev2IdcApplicationNotExists message {mutate_message!r}"
    )


def _ensure_idc_instance(ctx, sso_admin) -> str:
    """Create-or-adopt the account's IAM Identity Center instance.

    ``sso-admin:CreateInstance`` self-provisions a standalone (non-organization)
    instance, so an absent instance is a prerequisite this check can satisfy itself
    rather than an external one. The instance is an account-global singleton left
    in place for sibling checks, never torn down by this check's cleanup.

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


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_app(redshift, app_arn: str) -> None:
    try:
        redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "Qev2IdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
